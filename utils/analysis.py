"""Traffic analysis utilities for campus network data."""

import time
from typing import Any, Dict, List, Optional

import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path


class TrafficAnalyzer:
    """Campus network traffic analysis class."""

    _cache: Dict[str, Any] = {}
    _cache_ttl: Dict[str, float] = {}

    def _cache_result(self, key: str, ttl: int = 300) -> Any:
        """Get cached result if valid, else return sentinel to recompute."""
        now = time.time()
        if key in self._cache and now < self._cache_ttl.get(key, 0):
            return self._cache[key]
        return None

    def _set_cache(self, key: str, value: Any, ttl: int = 300) -> None:
        """Store a value in the cache with a TTL in seconds."""
        self._cache[key] = value
        self._cache_ttl[key] = time.time() + ttl

    def _invalidate_cache(self, key: Optional[str] = None) -> None:
        """Invalidate a specific cache key or clear all."""
        if key:
            self._cache.pop(key, None)
            self._cache_ttl.pop(key, None)
        else:
            self._cache.clear()
            self._cache_ttl.clear()
    
    def __init__(self, csv_path: str) -> None:
        """Initialize the analyzer and load the CSV file."""
        self.csv_path: str = csv_path
        self.df: Optional[pd.DataFrame] = None
        self.load_data()
    
    def load_data(self) -> bool:
        """Load the CSV file into a DataFrame."""
        try:
            self.df = pd.read_csv(self.csv_path)
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            self.df['hour'] = self.df['timestamp'].dt.hour
            self.df['date'] = self.df['timestamp'].dt.date
            return True
        except Exception as e:
            print(f"数据加载失败: {e}")
            return False
    
    def get_total_traffic(self) -> Dict[str, Any]:
        """Return total traffic statistics."""
        if self.df is None or len(self.df) == 0:
            return {"total_bytes": 0, "total_packets": 0, "unique_users": 0}

        cached = self._cache_result('total_traffic')
        if cached is not None:
            return cached

        result = {
            "total_bytes": int(self.df['bytes'].sum()),
            "total_packets": len(self.df),
            "unique_users": self.df['user'].nunique(),
            "unique_ips": self.df['src_ip'].nunique() + self.df['dst_ip'].nunique()
        }
        self._set_cache('total_traffic', result, ttl=300)
        return result
    
    def get_user_traffic_ranking(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Return user traffic rankings."""
        if self.df is None or len(self.df) == 0:
            return []

        cache_key = f'user_traffic_ranking_{top_n}'
        cached = self._cache_result(cache_key)
        if cached is not None:
            return cached

        user_traffic = self.df.groupby('user')['bytes'].sum().sort_values(ascending=False).head(top_n)
        result = [{"user": user, "bytes": int(bytes_val)} for user, bytes_val in user_traffic.items()]
        self._set_cache(cache_key, result, ttl=300)
        return result

    def get_user_ranking_by_packets(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Return user rankings by packet count."""
        if self.df is None or len(self.df) == 0:
            return []
        cache_key = f'user_ranking_by_packets_{top_n}'
        cached = self._cache_result(cache_key)
        if cached is not None:
            return cached
        user_packets = self.df.groupby('user')['timestamp'].count().sort_values(ascending=False).head(top_n)
        result = [{"user": user, "packets": int(count)} for user, count in user_packets.items()]
        self._set_cache(cache_key, result, ttl=300)
        return result

    def get_protocol_count(self) -> Dict[str, int]:
        """Return count of events per protocol."""
        if self.df is None or len(self.df) == 0:
            return {}
        cached = self._cache_result('protocol_count')
        if cached is not None:
            return cached
        result = self.df['protocol'].value_counts().to_dict()
        result = {str(k): int(v) for k, v in result.items()}
        self._set_cache('protocol_count', result, ttl=300)
        return result
    
    def get_app_category_traffic(self) -> List[Dict[str, Any]]:
        """Return traffic distribution by application category."""
        if self.df is None or len(self.df) == 0:
            return []

        cached = self._cache_result('app_category_traffic')
        if cached is not None:
            return cached

        app_traffic = self.df.groupby('app_category')['bytes'].sum().sort_values(ascending=False)
        result = [{"category": cat, "bytes": int(bytes_val)} for cat, bytes_val in app_traffic.items()]
        self._set_cache('app_category_traffic', result, ttl=300)
        return result
    
    def get_traffic_trend(self, unit: str = 'hour') -> List[Dict[str, Any]]:
        """Return traffic trend data over time."""
        if self.df is None or len(self.df) == 0:
            return []
        
        if unit == 'hour':
            trend = self.df.set_index('timestamp').resample('h')['bytes'].sum()
        else:
            trend = self.df.set_index('timestamp').resample('5min')['bytes'].sum()
        
        result = []
        for timestamp, bytes_val in trend.items():
            result.append({"time": str(timestamp), "bytes": int(bytes_val)})
        return result
    
    def get_active_hours(self) -> List[Dict[str, Any]]:
        """Return hourly user activity analysis."""
        if self.df is None or len(self.df) == 0:
            return []

        cached = self._cache_result('active_hours')
        if cached is not None:
            return cached

        # 按小时统计用户活跃度
        hourly_stats = self.df.groupby('hour').agg({
            'user': 'nunique',
            'bytes': 'sum',
            'timestamp': 'count'
        }).reset_index()
        
        hourly_stats.columns = ['hour', 'active_users', 'total_bytes', 'packet_count']
        hourly_stats['hour'] = hourly_stats['hour'].astype(str).str.zfill(2) + ':00'

        result = hourly_stats.to_dict('records')
        self._set_cache('active_hours', result, ttl=300)
        return result
    
    def get_user_app_distribution(self, user_id: str) -> List[Dict[str, Any]]:
        """Return application category distribution for a user."""
        if self.df is None or len(self.df) == 0:
            return []
        
        user_data = self.df[self.df['user'] == user_id]
        if len(user_data) == 0:
            return []
        
        app_dist = user_data.groupby('app_category')['bytes'].sum().sort_values(ascending=False)
        return [{"category": cat, "bytes": int(bytes_val)} for cat, bytes_val in app_dist.items()]

    def get_protocol_distribution(self) -> Dict[str, Any]:
        """Return bytes per protocol."""
        if self.df is None or len(self.df) == 0:
            return {}
        protocol_bytes = self.df.groupby('protocol')['bytes'].sum().to_dict()
        return {str(k): int(v) for k, v in protocol_bytes.items()}

    def get_top_talkers(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Return top source IPs by total bytes."""
        if self.df is None or len(self.df) == 0:
            return []
        top_ips = self.df.groupby('src_ip')['bytes'].sum().sort_values(ascending=False).head(top_n)
        return [{"src_ip": ip, "bytes": int(bytes_val)} for ip, bytes_val in top_ips.items()]

    def filter_by_date_range(self, start_date: str, end_date: str) -> pd.DataFrame:
        """Filter the dataframe to a date range (inclusive)."""
        if self.df is None or len(self.df) == 0:
            return pd.DataFrame()
        start = pd.Timestamp(start_date).date()
        end = pd.Timestamp(end_date).date()
        return self.df[(self.df['date'] >= start) & (self.df['date'] <= end)].copy()

    def get_hourly_averages(self) -> List[Dict[str, Any]]:
        """Return average bytes per hour across all days."""
        if self.df is None or len(self.df) == 0:
            return []
        hourly_avg = self.df.groupby('hour')['bytes'].mean().reset_index()
        hourly_avg.columns = ['hour', 'avg_bytes']
        hourly_avg['hour'] = hourly_avg['hour'].astype(str).str.zfill(2) + ':00'
        return hourly_avg.to_dict('records')

    def get_daily_stats(self) -> List[Dict[str, Any]]:
        """Return total bytes and packets per day."""
        if self.df is None or len(self.df) == 0:
            return []
        daily = self.df.groupby('date').agg(
            total_bytes=('bytes', 'sum'),
            total_packets=('timestamp', 'count')
        ).reset_index()
        daily['date'] = daily['date'].astype(str)
        return daily.to_dict('records')

    def get_traffic_growth(self) -> float:
        if self.df is None or len(self.df) == 0:
            return 0.0
        daily = self.df.groupby('date')['bytes'].sum().sort_index()
        if len(daily) < 2:
            return 0.0
        latest = daily.iloc[-1]
        previous = daily.iloc[-2]
        if previous == 0:
            return 0.0
        return round((latest - previous) / previous * 100, 2)

    def sample_data(self, fraction: float = 0.1, random_state: Optional[int] = None) -> pd.DataFrame:
        """Return a random sample of the dataframe for large dataset exploration."""
        if self.df is None or len(self.df) == 0:
            return pd.DataFrame()
        n = max(1, int(len(self.df) * fraction))
        return self.df.sample(n=n, random_state=random_state)

    def get_user_count(self) -> int:
        if self.df is None or len(self.df) == 0:
            return 0
        return int(self.df['user'].nunique())

    def get_top_ports(self, top_n: int = 10) -> List[Dict[str, Any]]:
        if self.df is None or len(self.df) == 0:
            return []
        port_traffic = self.df.groupby('dst_port')['bytes'].sum().sort_values(ascending=False).head(top_n)
        return [{"port": int(port), "bytes": int(bytes_val)} for port, bytes_val in port_traffic.items()]

    def get_tls_ratio(self) -> float:
        if self.df is None or len(self.df) == 0:
            return 0.0
        total = self.df['bytes'].sum()
        if total == 0:
            return 0.0
        tls_bytes = self.df[self.df['dst_port'] == 443]['bytes'].sum()
        return round(tls_bytes / total * 100, 2)

    def get_packet_size_stats(self) -> Dict[str, float]:
        if self.df is None or len(self.df) == 0:
            return {"min": 0, "max": 0, "avg": 0, "median": 0}
        return {
            "min": float(self.df['bytes'].min()),
            "max": float(self.df['bytes'].max()),
            "avg": float(round(self.df['bytes'].mean(), 2)),
            "median": float(self.df['bytes'].median()),
        }

    def get_hourly_user_activity(self) -> List[Dict[str, Any]]:
        if self.df is None or len(self.df) == 0:
            return []
        hourly_users = self.df.groupby('hour')['user'].nunique().reset_index()
        hourly_users.columns = ['hour', 'active_users']
        hourly_users['hour'] = hourly_users['hour'].astype(str).str.zfill(2) + ':00'
        return hourly_users.to_dict('records')

    def get_concurrent_users(self) -> List[Dict[str, Any]]:
        """Return number of active users per hour bucket."""
        if self.df is None or len(self.df) == 0:
            return []
        hourly_users = self.df.groupby(['date', 'hour'])['user'].nunique().reset_index()
        hourly_users.columns = ['date', 'hour', 'active_users']
        hourly_users['date'] = hourly_users['date'].astype(str)
        hourly_users['hour'] = hourly_users['hour'].astype(str).str.zfill(2) + ':00'
        return hourly_users.to_dict('records')

    def get_peak_traffic_hour(self) -> Optional[int]:
        """Return the hour with the highest total traffic."""
        if self.df is None or len(self.df) == 0:
            return None
        hourly = self.df.groupby('hour')['bytes'].sum()
        if len(hourly) == 0:
            return None
        return int(hourly.idxmax())

    def get_idle_periods(self, threshold_bytes: int = 100) -> List[int]:
        """Return hours with zero or minimal traffic (below threshold)."""
        if self.df is None or len(self.df) == 0:
            return []
        hourly = self.df.groupby('hour')['bytes'].sum()
        idle = [int(h) for h in range(24) if h not in hourly.index or hourly[h] <= threshold_bytes]
        return idle

    def get_user_agent_analysis(self) -> Dict[str, Any]:
        """Stub: return mock user agent breakdown."""
        return {
            "chrome": 45.0,
            "firefox": 20.0,
            "safari": 15.0,
            "edge": 10.0,
            "other": 10.0,
        }

    def get_heatmap_data(self) -> List[Dict[str, Any]]:
        if self.df is None or len(self.df) == 0:
            return []
        self.df['day_of_week'] = self.df['timestamp'].dt.dayofweek
        heatmap = self.df.groupby(['day_of_week', 'hour'])['bytes'].sum().reset_index()
        heatmap.columns = ['day_of_week', 'hour', 'bytes']
        return heatmap.to_dict('records')

    def get_anomaly_timeline(self) -> List[Dict[str, Any]]:
        if self.df is None or len(self.df) == 0:
            return []
        timeline = self.df.set_index('timestamp').resample('h').agg(
            total_bytes=('bytes', 'sum'),
            packet_count=('timestamp', 'count')
        ).reset_index()
        mean_bytes = timeline['total_bytes'].mean()
        std_bytes = timeline['total_bytes'].std()
        if std_bytes == 0:
            std_bytes = 1
        timeline['anomaly_score'] = timeline['total_bytes'].apply(
            lambda x: min(1.0, abs(x - mean_bytes) / (3 * std_bytes))
        )
        result = []
        for _, row in timeline.iterrows():
            result.append({
                "time": str(row['timestamp']),
                "total_bytes": int(row['total_bytes']),
                "packet_count": int(row['packet_count']),
                "anomaly_score": round(row['anomaly_score'], 4)
            })
        return result

    def get_comparison(self, user_a: str, user_b: str) -> Dict[str, Any]:
        if self.df is None or len(self.df) == 0:
            return {}
        ua = self.df[self.df['user'] == user_a]
        ub = self.df[self.df['user'] == user_b]
        def _summarize(u: pd.DataFrame, uid: str) -> Dict[str, Any]:
            if len(u) == 0:
                return {"user": uid, "total_bytes": 0, "total_packets": 0, "protocols": {}, "categories": {}, "active_hours": 0}
            return {
                "user": uid,
                "total_bytes": int(u['bytes'].sum()),
                "total_packets": len(u),
                "protocols": u.groupby('protocol')['bytes'].sum().apply(int).to_dict(),
                "categories": u.groupby('app_category')['bytes'].sum().apply(int).to_dict(),
                "active_hours": int(u['hour'].nunique()),
            }
        return {
            "user_a": _summarize(ua, user_a),
            "user_b": _summarize(ub, user_b),
            "diff": {
                "bytes_diff": int(ua['bytes'].sum() - ub['bytes'].sum()),
                "packets_diff": len(ua) - len(ub),
            }
        }

    @staticmethod
    def get_application_port_mapping() -> Dict[str, List[int]]:
        """Return a mapping of app categories to commonly used ports."""
        return {
            "web": [80, 443, 8080, 8443],
            "dns": [53],
            "email": [25, 110, 143, 587, 993, 995],
            "remote_access": [22, 23, 3389, 5900],
            "database": [3306, 5432, 1521, 1433, 6379, 27017],
            "file_transfer": [21, 445, 2049],
            "chat": [5222, 8448],
            "streaming": [1935, 554],
        }

def generate_traffic_trend_chart(analyzer: TrafficAnalyzer) -> str:
    """Generate a traffic trend line chart as HTML."""
    trend_data = analyzer.get_traffic_trend('hour')
    
    if not trend_data:
        return "<p>暂无数据</p>"
    
    times = [item['time'] for item in trend_data]
    bytes_vals = [item['bytes'] / (1024**2) for item in trend_data]  # 转换为 MB
    
    fig = go.Figure(data=[
        go.Scatter(
            x=times,
            y=bytes_vals,
            mode='lines+markers',
            name='流量 (MB)',
            line=dict(color='#1f77b4', width=2),
            marker=dict(size=6)
        )
    ])
    
    fig.update_layout(
        title='流量趋势分析',
        xaxis_title='时间',
        yaxis_title='流量 (MB)',
        hovermode='x unified',
        template='plotly_white',
        height=400
    )
    
    return fig.to_html(div_id="traffic_trend_chart", include_plotlyjs=False)


def generate_app_category_pie_chart(analyzer: TrafficAnalyzer) -> str:
    """Generate an application category pie chart as HTML."""
    app_data = analyzer.get_app_category_traffic()
    
    if not app_data:
        return "<p>暂无数据</p>"
    
    categories = [item['category'] for item in app_data]
    bytes_vals = [item['bytes'] / (1024**2) for item in app_data]  # 转换为 MB
    
    fig = go.Figure(data=[go.Pie(
        labels=categories,
        values=bytes_vals,
        hovertemplate='<b>%{label}</b><br>流量: %{value:.2f} MB<extra></extra>'
    )])
    
    fig.update_layout(
        title='应用类别流量分布',
        height=400
    )
    
    return fig.to_html(div_id="app_category_pie_chart", include_plotlyjs=False)


def generate_user_ranking_chart(analyzer: TrafficAnalyzer) -> str:
    """Generate a user traffic ranking bar chart as HTML."""
    user_data = analyzer.get_user_traffic_ranking(top_n=15)
    
    if not user_data:
        return "<p>暂无数据</p>"
    
    users = [item['user'] for item in user_data]
    bytes_vals = [item['bytes'] / (1024**2) for item in user_data]  # 转换为 MB
    
    fig = go.Figure(data=[
        go.Bar(
            y=users,
            x=bytes_vals,
            orientation='h',
            marker=dict(color='#ff7f0e'),
            hovertemplate='<b>%{y}</b><br>流量: %{x:.2f} MB<extra></extra>'
        )
    ])
    
    fig.update_layout(
        title='用户流量排行 TOP 15',
        xaxis_title='流量 (MB)',
        yaxis_title='用户',
        height=450,
        template='plotly_white',
        yaxis={'categoryorder': 'total ascending'}
    )
    
    return fig.to_html(div_id="user_ranking_chart", include_plotlyjs=False)


def generate_active_hours_chart(analyzer: TrafficAnalyzer) -> str:
    """Generate an active hours line chart as HTML."""
    active_data = analyzer.get_active_hours()
    
    if not active_data:
        return "<p>暂无数据</p>"
    
    hours = [item['hour'] for item in active_data]
    active_users = [item['active_users'] for item in active_data]
    traffic = [item['total_bytes'] / (1024**2) for item in active_data]  # 转换为 MB
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=hours,
        y=active_users,
        name='活跃用户数',
        yaxis='y1',
        line=dict(color='#2ca02c', width=2),
        marker=dict(size=6)
    ))
    
    fig.add_trace(go.Scatter(
        x=hours,
        y=traffic,
        name='流量 (MB)',
        yaxis='y2',
        line=dict(color='#d62728', width=2),
        marker=dict(size=6)
    ))
    
    fig.update_layout(
    title='活跃时段分析',
    xaxis_title='时间',
    yaxis=dict(
        title=dict(
            text='活跃用户数',
            font=dict(color='#2ca02c')
        ),
        tickfont=dict(color='#2ca02c')
    ),
    yaxis2=dict(
        title=dict(
            text='流量 (MB)',
            font=dict(color='#d62728')
        ),
        tickfont=dict(color='#d62728'),
        anchor='x',
        overlaying='y'
    ),
    hovermode='x unified',
    template='plotly_white',
    height=400,
    legend=dict(x=0.01, y=0.99)
)
    
    return fig.to_html(div_id="active_hours_chart", include_plotlyjs=False)


def generate_all_charts(analyzer: TrafficAnalyzer) -> Dict[str, str]:
    """Generate all charts as HTML."""
    return {
        'traffic_trend': generate_traffic_trend_chart(analyzer),
        'app_category': generate_app_category_pie_chart(analyzer),
        'user_ranking': generate_user_ranking_chart(analyzer),
        'active_hours': generate_active_hours_chart(analyzer)
    }
