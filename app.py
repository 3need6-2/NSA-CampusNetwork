"""Flask web application for campus network traffic analysis and monitoring."""

from typing import Any, Dict, List, Optional, Tuple, Union

from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, Response, stream_with_context, make_response
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
from utils.analysis import TrafficAnalyzer, generate_all_charts
from utils.user_profile import UserProfileAnalyzer
from utils.ai_security import AISecurityAnalyzer
from utils.ml_anomaly import detect_anomalies
from utils.realtime import ReplayEngine, stream_events

app = Flask(__name__)

limiter = Limiter(app=app, key_func=get_remote_address)

UPLOAD_FOLDER = Path(__file__).parent / 'data'
ALLOWED_EXTENSIONS = {'csv'}
MAX_CONTENT_LENGTH = 50 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'nsa-campus-network-dev-key')

UPLOAD_FOLDER.mkdir(exist_ok=True)


@app.after_request
def add_cors_headers(response: Response) -> Response:
    """Add CORS headers to all responses."""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
    return response

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
)
logger = logging.getLogger('nsa.app')


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

        charts_html = generate_all_charts(analyzer)

        user_profile_analyzer = UserProfileAnalyzer(str(csv_path))
        user_profiles = user_profile_analyzer.analyze_all_users()

        profiles_path = UPLOAD_FOLDER / 'user_profiles.json'
        user_profile_analyzer.save_profiles(str(profiles_path))

        ai_security_report = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
        ml_anomaly_report = detect_anomalies(analyzer.df)

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

        ok, err = load_analyzer(filepath)
        if ok:
            flash('上传并分析完成，已切换到最新数据。', 'success')
            return redirect(url_for('dashboard'))

        flash(err or '上传失败，请检查 CSV 内容。', 'danger')
        return redirect(url_for('index'))
    except Exception as exc:
        logger.exception('文件上传失败')
        flash(f'文件上传失败: {exc}', 'danger')
        return redirect(url_for('index'))


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


@app.route('/api/dashboard_data')
def api_dashboard_data() -> Response:
    """API endpoint returning complete dashboard data."""
    snap = state.snapshot()
    analyzer = snap['analyzer']
    if not analyzer:
        return jsonify({'error': 'no_data', 'message': '请先上传 CSV 流量数据。'}), 404

    security_report = snap['ai_security_report']
    if not security_report:
        security_report = AISecurityAnalyzer(analyzer.df).generate_report(include_deepseek=False)
        state.update_security_report(security_report)

    return jsonify({
        'total_traffic': analyzer.get_total_traffic(),
        'user_ranking': analyzer.get_user_traffic_ranking(top_n=15),
        'app_category': analyzer.get_app_category_traffic(),
        'active_hours': analyzer.get_active_hours(),
        'attack_map': _attack_map_stats(analyzer, security_report),
        'ai_security': security_report,
        'ml_anomaly': snap['ml_anomaly_report'] or detect_anomalies(analyzer.df),
    })


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
    snap = state.snapshot()
    if snap['user_profiles']:
        return jsonify(snap['user_profiles'])

    profiles_path = UPLOAD_FOLDER / 'user_profiles.json'
    if profiles_path.exists():
        try:
            with open(profiles_path, 'r', encoding='utf-8') as f:
                return jsonify(json.load(f))
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
