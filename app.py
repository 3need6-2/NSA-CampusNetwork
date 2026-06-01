"""Flask web application for campus network traffic analysis and monitoring."""

from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response, stream_with_context, make_response, after_this_request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from io import StringIO
import pandas as pd
from pathlib import Path
import os
import json
import logging
import threading
import time
import concurrent.futures
from utils.analysis import TrafficAnalyzer, generate_all_charts
from utils.user_profile import UserProfileAnalyzer
from utils.ai_security import AISecurityAnalyzer
from utils.ml_anomaly import detect_anomalies
from utils.realtime import ReplayEngine, stream_events
from utils.metrics import registry, requests_total, bytes_processed, alerts_total, request_duration
from utils.cache import cache

app = Flask(__name__)

limiter = Limiter(app=app, key_func=get_remote_address)

UPLOAD_FOLDER = Path(__file__).parent / 'data'
ALLOWED_EXTENSIONS = {'csv'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024
REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '300'))

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.config['REQUEST_TIMEOUT'] = REQUEST_TIMEOUT
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'nsa-campus-network-dev-key')

UPLOAD_FOLDER.mkdir(exist_ok=True)


@app.after_request
def add_cors_headers(response: Response) -> Response:
    """Add CORS headers to all responses."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response


@app.after_request
def add_gzip_compression(response: Response) -> Response:
    """Apply gzip compression to text responses if accepted by client."""
    return compress_response(response)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger('nsa.app')


def compress_response(response: Response) -> Response:
    """Apply gzip compression to text responses if accepted by client."""
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding:
        return response
    if response.content_length and response.content_length < 500:
        return response
    if response.mimetype and not response.mimetype.startswith(('text/', 'application/json', 'application/javascript')):
        return response

    import gzip
    response.direct_passthrough = False
    payload = response.get_data()
    compressed = gzip.compress(payload)
    response.set_data(compressed)
    response.headers['Content-Encoding'] = 'gzip'
    response.headers['Content-Length'] = len(compressed)
    response.headers['Vary'] = 'Accept-Encoding'
    return response


@app.before_request
def before_request_timing() -> None:
    request._start_time = time.time()


@app.after_request
def after_request_timing(response: Response) -> Response:
    labels = {'method': request.method, 'endpoint': request.endpoint or 'unknown', 'status': str(response.status_code)}
    requests_total(labels)
    if hasattr(request, '_start_time'):
        duration = time.time() - request._start_time
        request_duration(duration, labels)
        logger.debug('Request %s %s took %.3fs', request.method, request.path, duration)
    return response


class AnalyzerState:
    """Thread-safe global analyzer state container."""

    def __init__(self) -> None:
        self._lock: threading.RLock = threading.RLock()
        self.analyzer: Optional[TrafficAnalyzer] = None
        self.user_profile_analyzer: Optional[UserProfileAnalyzer] = None
        self.charts_html: Dict[str, str] = {}
        self.user_profiles: Dict[str, Any] = {}
        self.ai_security_report: Dict[str, Any] = {}
        self.ml_anomaly_report: Dict[str, Any] = {}

    def replace(self, analyzer: TrafficAnalyzer, user_profile_analyzer: UserProfileAnalyzer, charts_html: Dict[str, str], user_profiles: Dict[str, Any], ai_security_report: Dict[str, Any], ml_anomaly_report: Dict[str, Any]) -> None:
        """Replace the current state with new analyzer data."""
        with self._lock:
            self.analyzer = analyzer
            self.user_profile_analyzer = user_profile_analyzer
            self.charts_html = charts_html
            self.user_profiles = user_profiles
            self.ai_security_report = ai_security_report
            self.ml_anomaly_report = ml_anomaly_report

    def snapshot(self) -> Dict[str, Any]:
        """Return a thread-safe snapshot of the current state."""
        with self._lock:
            return {
                'analyzer': self.analyzer,
                'user_profile_analyzer': self.user_profile_analyzer,
                'charts_html': self.charts_html,
                'user_profiles': self.user_profiles,
                'ai_security_report': self.ai_security_report,
                'ml_anomaly_report': self.ml_anomaly_report,
            }

    def update_security_report(self, report: Dict[str, Any]) -> None:
        """Update the AI security report in a thread-safe manner."""
        with self._lock:
            self.ai_security_report = report

    def update_ml_report(self, report: Dict[str, Any]) -> None:
        """Update the ML anomaly report in a thread-safe manner."""
        with self._lock:
            self.ml_anomaly_report = report


state = AnalyzerState()


def run_with_timeout(func, timeout: int, *args, **kwargs):
    """Run a function with a timeout using a thread pool."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            logger.error('Function %s timed out after %ds', func.__name__, timeout)
            raise concurrent.futures.TimeoutError(f'{func.__name__} timed out after {timeout}s')


def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def load_analyzer(csv_file: Optional[Union[str, Path]] = None) -> Tuple[bool, Optional[str]]:
    """Load the analyzer, generate charts, profiles, and security reports."""
    csv_path = csv_file if csv_file is not None else UPLOAD_FOLDER / 'traffic.csv'

    if not csv_path.exists():
        return False, f'未找到 CSV 文件: {csv_path.name}'

    try:
        analyzer = TrafficAnalyzer(str(csv_path))
        if analyzer.df is None or len(analyzer.df) == 0:
            return False, 'CSV 文件为空或解析失败，请检查格式。'

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            future_charts = pool.submit(generate_all_charts, analyzer)
            future_profiles = pool.submit(_build_user_profiles, str(csv_path))
            future_security = pool.submit(AISecurityAnalyzer(analyzer.df).generate_report, include_deepseek=False)
            future_ml = pool.submit(detect_anomalies, analyzer.df)

            charts_html = future_charts.result()
            user_profile_analyzer, user_profiles = future_profiles.result()
            ai_security_report = future_security.result()
            ml_anomaly_report = future_ml.result()

        profiles_path = UPLOAD_FOLDER / 'user_profiles.json'
        user_profile_analyzer.save_profiles(str(profiles_path))

        state.replace(
            analyzer=analyzer,
            user_profile_analyzer=user_profile_analyzer,
            charts_html=charts_html,
            user_profiles=user_profiles,
            ai_security_report=ai_security_report,
            ml_anomaly_report=ml_anomaly_report,
        )
        logger.info('分析器加载成功: %s 条记录, %s 个用户, %s 个 ML 异常用户',
                    len(analyzer.df), analyzer.df['user'].nunique(),
                    ml_anomaly_report.get('summary', {}).get('anomaly_users', 0))
        return True, None
    except Exception as exc:
        logger.exception('分析器加载失败')
        return False, f'分析器加载失败: {exc}'


def _build_user_profiles(csv_path: str):
    """Build user profiles helper for thread pool execution."""
    profile_analyzer = UserProfileAnalyzer(csv_path)
    profiles = profile_analyzer.analyze_all_users()
    return profile_analyzer, profiles


@app.route('/')
def index() -> str:
    """Index page showing basic information and upload form."""
    snap = state.snapshot()
    total_traffic = {}
    if snap['analyzer']:
        total_traffic = snap['analyzer'].get_total_traffic()

    return render_template('index.html', total_traffic=total_traffic)


@app.route('/dashboard')
def dashboard() -> str:
    """Dashboard page displaying all traffic charts."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        flash('请先上传 CSV 流量数据再查看仪表板。', 'warning')
        return redirect(url_for('index'))

    total_traffic = analyzer.get_total_traffic()
    user_ranking = analyzer.get_user_traffic_ranking(top_n=10)
    app_category = analyzer.get_app_category_traffic()
    active_hours = analyzer.get_active_hours()
    attack_map = _attack_map_stats(analyzer, snap['ai_security_report'])

    return render_template('dashboard.html',
                          charts_html=snap['charts_html'],
                          total_traffic=total_traffic,
                          user_ranking=user_ranking,
                          app_category=app_category,
                          active_hours=active_hours,
                          ai_security=snap['ai_security_report'],
                          ml_anomaly=snap['ml_anomaly_report'],
                          attack_map=attack_map)


def _attack_map_stats(analyzer: Optional[TrafficAnalyzer], security_report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate attack source tracking summary metrics."""
    if not analyzer or analyzer.df is None or len(analyzer.df) == 0:
        return {'sources': 0, 'top_target': '暂无', 'blocked': 0}

    df = analyzer.df
    sources = df['src_ip'].nunique() if 'src_ip' in df.columns else 0
    blocked = len(security_report.get('blocked_entities', [])) if security_report else 0
    top_target = '暂无'

    if 'dst_port' in df.columns and len(df['dst_port']) > 0:
        top_port = int(df['dst_port'].mode().iloc[0])
        service_names = {
            22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS',
            3306: 'MySQL', 3389: 'RDP', 6379: 'Redis',
        }
        service = service_names.get(top_port, 'TCP/UDP')
        top_target = f"Port {top_port} ({service})"

    return {'sources': int(sources), 'top_target': top_target, 'blocked': blocked}


@app.route('/upload', methods=['POST'])
@limiter.limit("5 per minute")
def upload() -> str:
    """Handle CSV file upload and trigger analysis."""
    if 'file' not in request.files:
        flash('未选择文件，请重新上传。', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']

    if file.filename == '':
        flash('文件名为空，请选择有效的 CSV 文件。', 'danger')
        return redirect(url_for('index'))

    if not allowed_file(file.filename):
        flash('只支持 CSV 格式文件。', 'danger')
        return redirect(url_for('index'))

    try:
        filename = secure_filename('traffic.csv')
        filepath = UPLOAD_FOLDER / filename
        file.save(str(filepath))

        df_check = pd.read_csv(filepath)
        required_columns = {'timestamp', 'bytes', 'user', 'src_ip', 'dst_ip', 'dst_port', 'app_category', 'protocol'}
        missing = required_columns - set(df_check.columns)
        if missing:
            flash(f'CSV 文件缺少必需列: {", ".join(sorted(missing))}', 'danger')
            filepath.unlink(missing_ok=True)
            return redirect(url_for('index'))

        ok, err = run_with_timeout(load_analyzer, app.config['REQUEST_TIMEOUT'], filepath)
        if ok:
            flash('上传并分析完成，已切换到最新数据。', 'success')
            return redirect(url_for('dashboard'))

        flash(err or '上传失败，请检查 CSV 内容。', 'danger')
        return redirect(url_for('index'))
    except concurrent.futures.TimeoutError:
        flash(f'分析超时（超过 {app.config["REQUEST_TIMEOUT"]} 秒），文件可能过大。', 'danger')
        return redirect(url_for('index'))
    except Exception as exc:
        logger.exception('文件上传失败')
        flash(f'文件上传失败: {exc}', 'danger')
        return redirect(url_for('index'))


@app.route('/api/analyze/batch', methods=['POST'])
@limiter.limit("2 per minute")
def api_analyze_batch() -> Response:
    """Accept multiple CSV files for batch analysis."""
    files = request.files.getlist('file')
    if not files:
        return jsonify({'error': 'no_files', 'message': '请上传至少一个 CSV 文件。'}), 400

    results = []
    errors = []

    for file in files:
        if file.filename == '' or not allowed_file(file.filename):
            errors.append({'file': file.filename, 'error': '不支持的文件格式'})
            continue

        try:
            filename = secure_filename(f'batch_{int(time.time())}_{file.filename}')
            filepath = UPLOAD_FOLDER / filename
            file.save(str(filepath))

            ok, err = run_with_timeout(load_analyzer, app.config['REQUEST_TIMEOUT'], filepath)
            if ok:
                snap = state.snapshot()
                results.append({
                    'file': file.filename,
                    'status': 'success',
                    'total_records': len(snap['analyzer'].df) if snap['analyzer'] else 0,
                    'total_traffic': snap['analyzer'].get_total_traffic() if snap['analyzer'] else {},
                })
            else:
                errors.append({'file': file.filename, 'error': err})
        except concurrent.futures.TimeoutError:
            errors.append({'file': file.filename, 'error': f'分析超时（超过 {app.config["REQUEST_TIMEOUT"]} 秒）'})
        except Exception as exc:
            logger.exception('批量处理文件失败: %s', file.filename)
            errors.append({'file': file.filename, 'error': str(exc)})

    return jsonify({'results': results, 'errors': errors, 'total': len(files), 'success': len(results)})


@app.route('/api/data/sample')
def api_data_sample() -> Response:
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': 'No data loaded.'}), 404
    n = request.args.get('n', 5, type=int)
    n = max(1, min(n, 100))
    sample = analyzer.df.sample(n=n).to_dict('records')
    return jsonify({'sample': sample, 'count': len(sample)})


@app.route('/api/data/info')
def api_data_info() -> Response:
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': 'No data loaded.'}), 404
    df = analyzer.df
    return jsonify({
        'row_count': len(df),
        'columns': list(df.columns),
        'date_range': {'start': str(df['timestamp'].min()), 'end': str(df['timestamp'].max())},
        'unique_users': int(df['user'].nunique()),
        'total_bytes': int(df['bytes'].sum()),
    })


@app.route('/api/status')
def api_status() -> Response:
    import psutil
    snap = state.snapshot()
    uptime_seconds = time.time() - _process_start_time
    memory = psutil.Process().memory_info().rss
    return jsonify({
        'status': 'ok',
        'uptime_seconds': uptime_seconds,
        'memory_bytes': memory,
        'data_loaded': snap['analyzer'] is not None,
        'records_loaded': len(snap['analyzer'].df) if snap['analyzer'] else 0,
        'version': '1.0.0',
    })

_process_start_time = time.time()


@app.route('/api/config')
def api_config() -> Response:
    """Return current app configuration excluding secrets."""
    return jsonify({
        'upload_folder': str(app.config['UPLOAD_FOLDER']),
        'max_content_length': app.config['MAX_CONTENT_LENGTH'],
        'allowed_extensions': list(ALLOWED_EXTENSIONS),
        'debug': app.debug,
        'version': '1.0.0',
    })


@app.route('/api/health')
def api_health() -> Response:
    """Health check endpoint."""
    return jsonify({
        'status': 'ok',
        'timestamp': time.time(),
        'version': '1.0.0',
    })


@app.route('/api/metrics')
def api_metrics() -> Response:
    """Return Prometheus-style metrics."""
    return Response(registry.dump(), mimetype='text/plain; version=0.0.4')


@app.route('/api/stats')
def api_stats() -> Response:
    """API endpoint returning traffic statistics."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    return jsonify({
        'total_traffic': analyzer.get_total_traffic(),
        'user_ranking': analyzer.get_user_traffic_ranking(),
        'app_category': analyzer.get_app_category_traffic(),
        'active_hours': analyzer.get_active_hours()
    })


@app.route('/api/stats/detailed')
def api_stats_detailed() -> Response:
    """Return detailed stats including per-user averages, median traffic, and percentiles."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    df = analyzer.df
    total_bytes = int(df['bytes'].sum())
    total_packets = len(df)
    user_count = int(df['user'].nunique())
    per_user_avg = round(total_bytes / user_count, 2) if user_count > 0 else 0
    median_traffic = float(df['bytes'].median())
    percentiles = {
        'p25': float(df['bytes'].quantile(0.25)),
        'p50': float(df['bytes'].quantile(0.50)),
        'p75': float(df['bytes'].quantile(0.75)),
        'p90': float(df['bytes'].quantile(0.90)),
        'p95': float(df['bytes'].quantile(0.95)),
        'p99': float(df['bytes'].quantile(0.99)),
    }

    return jsonify({
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'unique_users': user_count,
        'per_user_avg_bytes': per_user_avg,
        'median_traffic_bytes': median_traffic,
        'percentiles': percentiles,
    })


@app.route('/api/dashboard_data')
def api_dashboard_data() -> Response:
    """API endpoint returning complete dashboard data."""
    cached = cache.get('api_dashboard_data')
    if cached:
        return jsonify(cached)

    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    security_report = snap['ai_security_report']
    if not security_report:
        security_report = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
        state.update_security_report(security_report)

    data = {
        'total_traffic': analyzer.get_total_traffic(),
        'user_ranking': analyzer.get_user_traffic_ranking(top_n=15),
        'app_category': analyzer.get_app_category_traffic(),
        'active_hours': analyzer.get_active_hours(),
        'attack_map': _attack_map_stats(analyzer, security_report),
        'ai_security': security_report,
        'ml_anomaly': snap['ml_anomaly_report'] or detect_anomalies(analyzer.df),
    }
    cache.set('api_dashboard_data', data, ttl=60)
    return jsonify(data)


@app.route('/api/notify/test', methods=['POST'])
def api_notify_test() -> Response:
    payload = request.get_json(silent=True) or {}
    message = payload.get('message', 'Test notification')
    logger.info('Test notification: %s', message)
    return jsonify({'status': 'ok', 'message': message})


@app.route('/api/export/pdf')
def api_export_pdf() -> Response:
    return jsonify({'status': 'not_implemented', 'message': 'PDF export is not yet implemented.'}), 501


@app.route('/api/export/json')
def api_export_json() -> Response:
    """Export all analysis data as JSON download."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    data = {
        'total_traffic': analyzer.get_total_traffic(),
        'user_ranking': analyzer.get_user_traffic_ranking(),
        'app_category': analyzer.get_app_category_traffic(),
        'active_hours': analyzer.get_active_hours(),
        'user_profiles': snap['user_profiles'],
        'ai_security': snap['ai_security_report'],
        'ml_anomaly': snap['ml_anomaly_report'],
    }

    response = make_response(json.dumps(data, ensure_ascii=False, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = 'attachment; filename=analysis_export.json'
    return response


@app.route('/api/export/csv')
def api_export_csv() -> Response:
    """Export analysis data as CSV download."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer or analyzer.df is None:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    buf = StringIO()
    analyzer.df.to_csv(buf, index=False)
    buf.seek(0)

    response = make_response(buf.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=analysis_export.csv'
    return response


@app.route('/api/user_profiles')
def api_user_profiles() -> Response:
    """API endpoint returning user profile data."""
    cached = cache.get('api_user_profiles')
    if cached:
        return jsonify(cached)

    snap = state.snapshot()
    if snap['user_profiles']:
        cache.set('api_user_profiles', snap['user_profiles'], ttl=120)
        return jsonify(snap['user_profiles'])

    profiles_path = UPLOAD_FOLDER / 'user_profiles.json'
    if profiles_path.exists():
        try:
            with open(profiles_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                cache.set('api_user_profiles', data, ttl=120)
                return jsonify(data)
        except Exception:
            logger.exception('加载用户画像失败')

    return jsonify({})


@app.route('/api/ai_security')
def api_ai_security() -> Response:
    """API endpoint returning AI security analysis report."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    security_report = snap['ai_security_report']
    if not security_report:
        security_report = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
        state.update_security_report(security_report)

    return jsonify(security_report)


@app.route('/api/ai_security/deepseek', methods=['POST'])
def api_ai_security_deepseek() -> Response:
    """API endpoint running DeepSeek review on security report."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    report = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=True)
    state.update_security_report(report)
    return jsonify(report)


@app.route('/api/ml_anomaly')
def api_ml_anomaly() -> Response:
    """API endpoint returning ML anomaly detection results."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    report = snap['ml_anomaly_report']
    if not report:
        report = detect_anomalies(analyzer.df)
        state.update_ml_report(report)
    return jsonify(report)


@app.route('/api/ml_anomaly/refresh', methods=['POST'])
def api_ml_anomaly_refresh() -> Response:
    """API endpoint forcing a refresh of ML anomaly detection."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404
    report = detect_anomalies(analyzer.df)
    state.update_ml_report(report)
    return jsonify(report)


@app.route('/realtime')
def realtime_view() -> str:
    """Real-time situational awareness dashboard page."""
    snap = state.snapshot()
    if not snap['analyzer']:
        flash('请先上传 CSV 流量数据再进入实时大屏。', 'warning')
        return redirect(url_for('index'))
    return render_template('realtime.html')


@app.route('/api/realtime/start', methods=['POST'])
def api_realtime_start() -> Response:
    """API endpoint to start traffic replay."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    payload = request.get_json(silent=True) or {}
    rate = float(payload.get('rate', request.args.get('rate', 5.0)))
    loop = bool(payload.get('loop', request.args.get('loop', 'true').lower() != 'false'))
    result = ReplayEngine.instance().start(analyzer.df, rate=rate, loop=loop)
    return jsonify(result)


@app.route('/api/realtime/stop', methods=['POST'])
def api_realtime_stop() -> Response:
    """API endpoint to stop traffic replay."""
    return jsonify(ReplayEngine.instance().stop())


@app.route('/api/realtime/rate', methods=['POST'])
def api_realtime_rate() -> Response:
    """API endpoint to adjust replay rate on the fly."""
    payload = request.get_json(silent=True) or {}
    try:
        rate = float(payload.get('rate', request.args.get('rate', 5.0)))
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': '速率参数无效'}), 400
    return jsonify(ReplayEngine.instance().set_rate(rate))


@app.route('/api/realtime/status')
def api_realtime_status() -> Response:
    """API endpoint returning replay status and metrics."""
    return jsonify(ReplayEngine.instance().status())


@app.route('/api/alerts/history')
def api_alerts_history() -> Response:
    """Return all alerts with timestamps from the realtime engine's alert history."""
    alerts = ReplayEngine.instance().get_alert_history()
    return jsonify({
        'alerts': alerts,
        'count': len(alerts),
    })


@app.route('/api/realtime/stream')
def api_realtime_stream() -> Response:
    """SSE stream endpoint for real-time replay events."""
    stop_event = threading.Event()

    @stream_with_context
    def generate():
        try:
            for chunk in stream_events(stop_event):
                yield chunk
        except GeneratorExit:
            stop_event.set()
            raise

    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    return response


# ── API: Users ──────────────────────────────────────────────────────────────


@app.route('/api/users')
def api_users() -> Response:
    """Return list of all users."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    users = sorted(analyzer.df['user'].unique().tolist())
    return jsonify({'users': users, 'count': len(users)})


@app.route('/api/users/<user_id>/profile')
def api_user_profile(user_id: str) -> Response:
    """Return profile for a specific user."""
    snap = state.snapshot()
    if not snap['analyzer']:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    profile = snap['user_profiles'].get(user_id)
    if profile is None:
        return jsonify({'error': 'not_found', 'message': f'用户 {user_id} 不存在。'}), 404

    return jsonify({'user': user_id, 'profile': profile})


@app.route('/api/users/<user_id>/traffic')
def api_user_traffic(user_id: str) -> Response:
    """Return traffic data for a specific user."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    user_data = analyzer.df[analyzer.df['user'] == user_id]
    if len(user_data) == 0:
        return jsonify({'error': 'not_found', 'message': f'用户 {user_id} 不存在。'}), 404

    hourly = user_data.groupby('hour').agg({'bytes': 'sum', 'timestamp': 'count'}).reset_index()
    active_hours = [
        {'hour': int(r['hour']), 'bytes': int(r['bytes']), 'count': int(r['timestamp'])}
        for _, r in hourly.iterrows()
    ]

    return jsonify({
        'user': user_id,
        'total_bytes': int(user_data['bytes'].sum()),
        'packet_count': len(user_data),
        'unique_destinations': int(user_data['dst_ip'].nunique()),
        'app_distribution': analyzer.get_user_app_distribution(user_id),
        'active_hours': active_hours,
        'time_range': {
            'start': str(user_data['timestamp'].min()),
            'end': str(user_data['timestamp'].max()),
        },
    })


@app.route('/api/user/<user_id>/full-report')
def api_user_full_report(user_id: str) -> Response:
    """Return all available data for a user in one response."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    profile_analyzer = snap['user_profile_analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    user_data = analyzer.df[analyzer.df['user'] == user_id]
    if len(user_data) == 0:
        return jsonify({'error': 'not_found', 'message': f'用户 {user_id} 不存在。'}), 404

    if profile_analyzer is None:
        profile_analyzer = UserProfileAnalyzer(analyzer.csv_path)

    hourly = user_data.groupby('hour').agg({'bytes': 'sum', 'timestamp': 'count'}).reset_index()
    active_hours = [
        {'hour': int(r['hour']), 'bytes': int(r['bytes']), 'count': int(r['timestamp'])}
        for _, r in hourly.iterrows()
    ]

    return jsonify({
        'user': user_id,
        'total_bytes': int(user_data['bytes'].sum()),
        'packet_count': len(user_data),
        'unique_destinations': int(user_data['dst_ip'].nunique()),
        'app_distribution': analyzer.get_user_app_distribution(user_id),
        'active_hours': active_hours,
        'time_range': {
            'start': str(user_data['timestamp'].min()),
            'end': str(user_data['timestamp'].max()),
        },
        'traffic_ranking': analyzer.get_user_traffic_ranking(top_n=50)[:10],
        'protocol_distribution': analyzer.get_protocol_distribution(),
        'app_category': analyzer.get_app_category_traffic(),
        'encryption_ratio': profile_analyzer.get_encryption_ratio(user_id),
        'connection_frequency': profile_analyzer.get_connection_frequency(user_id),
        'peak_bandwidth': profile_analyzer.get_peak_bandwidth(user_id),
        'protocol_diversity': profile_analyzer.get_protocol_diversity(user_id),
        'download_upload_ratio': profile_analyzer.get_download_upload_ratio(user_id),
        'profile': snap['user_profiles'].get(user_id, {}),
    })


@app.route('/api/search')
def api_search() -> Response:
    """Search across users, IPs, and app categories."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    q = request.args.get('q', '').strip().lower()
    if not q:
        return jsonify({'error': 'missing_query', 'message': '请提供搜索参数 q。'}), 400

    df = analyzer.df
    mask = (
        df['user'].str.lower().str.contains(q, na=False)
        | df['src_ip'].str.contains(q, na=False)
        | df['dst_ip'].str.contains(q, na=False)
        | df['app_category'].str.lower().str.contains(q, na=False)
    )
    results = df[mask]

    return jsonify({
        'query': q,
        'total_matches': len(results),
        'total_bytes': int(results['bytes'].sum()) if len(results) > 0 else 0,
        'unique_users': int(results['user'].nunique()) if len(results) > 0 else 0,
        'sample': results.head(50).to_dict('records') if len(results) > 0 else [],
    })


@app.route('/api/traffic/timeline')
def api_traffic_timeline() -> Response:
    """Return traffic timeline with optional from/to filtering."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    df = analyzer.df.copy()
    from_str = request.args.get('from')
    to_str = request.args.get('to')

    if from_str:
        df = df[df['timestamp'] >= from_str]
    if to_str:
        df = df[df['timestamp'] <= to_str]

    trend = df.set_index('timestamp').resample('h')['bytes'].sum()
    timeline = [{'time': str(ts), 'bytes': int(b)} for ts, b in trend.items()]

    return jsonify({'timeline': timeline, 'count': len(timeline), 'from': from_str, 'to': to_str})


@app.route('/api/network/topology')
def api_network_topology() -> Response:
    """Return network topology data (unique src_ip to dst_ip connections)."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    edges = (
        analyzer.df.groupby(['src_ip', 'dst_ip'])
        .agg(connections=('bytes', 'count'), bytes=('bytes', 'sum'))
        .reset_index()
    )
    edges = edges.sort_values('connections', ascending=False)

    return jsonify({
        'nodes': {
            'sources': sorted(analyzer.df['src_ip'].unique().tolist()),
            'destinations': sorted(analyzer.df['dst_ip'].unique().tolist()),
        },
        'edges': [
            {'source': r['src_ip'], 'target': r['dst_ip'],
             'connections': int(r['connections']), 'bytes': int(r['bytes'])}
            for _, r in edges.iterrows()
        ],
        'total_edges': len(edges),
    })


@app.route('/api/traffic/protocols')
def api_traffic_protocols() -> Response:
    """Return protocol distribution data."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    proto = analyzer.df.groupby('protocol').agg({'bytes': 'sum', 'timestamp': 'count'}).reset_index()
    protocols = [
        {'protocol': r['protocol'], 'bytes': int(r['bytes']), 'packet_count': int(r['timestamp'])}
        for _, r in proto.iterrows()
    ]
    protocols.sort(key=lambda x: x['bytes'], reverse=True)
    total = sum(p['bytes'] for p in protocols)
    for p in protocols:
        p['percentage'] = round(p['bytes'] / total * 100, 2) if total > 0 else 0

    return jsonify({'protocols': protocols, 'total_bytes': total})


@app.route('/api/summary')
def api_summary() -> Response:
    """Return a combined summary of all analysis."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    ai_report = snap['ai_security_report'] or {}
    ml_report = snap['ml_anomaly_report'] or {}

    return jsonify({
        'total_traffic': analyzer.get_total_traffic(),
        'user_ranking': analyzer.get_user_traffic_ranking(top_n=5),
        'app_category': analyzer.get_app_category_traffic(),
        'active_hours': analyzer.get_active_hours(),
        'user_count': len(snap['user_profiles']),
        'security_summary': {
            'ai_threats': len(ai_report.get('threats', [])),
            'ml_anomalies': len(ml_report.get('anomalies', [])),
        },
    })


@app.route('/api/tags')
def api_tags() -> Response:
    """Return all unique tags across all users."""
    snap = state.snapshot()
    if not snap['analyzer']:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    all_tags = set()
    for profile in snap['user_profiles'].values():
        all_tags.update(profile.get('tags', []))

    return jsonify({'tags': sorted(all_tags), 'count': len(all_tags)})


@app.route('/api/tags/<tag>')
def api_tag_users(tag: str) -> Response:
    """Return users matching a specific tag."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    matched = []
    for user_id, profile in snap['user_profiles'].items():
        if tag in profile.get('tags', []):
            user_data = analyzer.df[analyzer.df['user'] == user_id]
            matched.append({
                'user': user_id,
                'category_pct': profile.get('category_pct'),
                'total_bytes': int(user_data['bytes'].sum()) if len(user_data) > 0 else 0,
            })

    return jsonify({'tag': tag, 'users': matched, 'count': len(matched)})


@app.template_filter('format_bytes')
def format_bytes(bytes_val: Union[int, float]) -> str:
    """Jinja template filter to format byte counts as human-readable strings."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 ** 2:
        return f"{bytes_val / 1024:.2f} KB"
    elif bytes_val < 1024 ** 3:
        return f"{bytes_val / (1024 ** 2):.2f} MB"
    else:
        return f"{bytes_val / (1024 ** 3):.2f} GB"


@app.errorhandler(404)
def not_found(error: Any) -> Tuple[str, int]:
    """Handle 404 Not Found errors."""
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error: Any) -> Tuple[str, int]:
    """Handle 500 Internal Server errors."""
    return render_template('500.html'), 500


@app.errorhandler(413)
def request_entity_too_large(error: Any) -> str:
    """Handle file too large error (HTTP 413)."""
    flash(f'文件过大，单次上传不能超过 {MAX_CONTENT_LENGTH // (1024 * 1024)} MB。', 'danger')
    return redirect(url_for('index'))


if __name__ == '__main__':
    ok, err = load_analyzer()
    if not ok:
        logger.warning('启动时未加载默认数据: %s', err)

    app.run(debug=True, host='0.0.0.0', port=5001)
