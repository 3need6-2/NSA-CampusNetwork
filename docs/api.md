# API Documentation

All API endpoints are served from `http://localhost:5001`.

## Web Pages

| Route        | Method | Description                                              |
| ------------ | ------ | -------------------------------------------------------- |
| `/`          | GET    | Home page - system overview, stats, and CSV upload form  |
| `/dashboard` | GET    | Security dashboard - charts, AI audit, ML anomalies      |
| `/realtime`  | GET    | Real-time situational awareness dashboard with SSE       |

## Data Endpoints

### GET /api/stats

Returns basic traffic statistics.

```bash
curl http://localhost:5001/api/stats
```

**Response:**

```json
{
  "total_traffic": {
    "total_bytes": 1234567,
    "total_packets": 456,
    "unique_users": 50,
    "unique_ips": 100
  },
  "user_ranking": [
    {"user": "student_001", "bytes": 123456}
  ],
  "app_category": [
    {"category": "Video Streaming", "bytes": 456789}
  ],
  "active_hours": [
    {"hour": "08:00", "active_users": 25, "total_bytes": 56789, "packet_count": 45}
  ]
}
```

### GET /api/dashboard_data

Returns complete dashboard data including stats, rankings, AI security, and ML anomalies.

```bash
curl http://localhost:5001/api/dashboard_data
```

### GET /api/user_profiles

Returns user profile data with tags, application distribution, and behavior analysis.

```bash
curl http://localhost:5001/api/user_profiles
```

### GET /api/ai_security

Returns local AI security audit report with risk levels, alerts, and blocking suggestions.

```bash
curl http://localhost:5001/api/ai_security
```

### POST /api/ai_security/deepseek

Triggers DeepSeek secondary review. Requires `DEEPSEEK_API_KEY` environment variable.

```bash
export DEEPSEEK_API_KEY="your-api-key"
curl -X POST http://localhost:5001/api/ai_security/deepseek
```

### GET /api/ml_anomaly

Returns IsolationForest anomaly detection results.

```bash
curl http://localhost:5001/api/ml_anomaly
```

### POST /api/ml_anomaly/refresh

Forces re-run of ML anomaly detection.

```bash
curl -X POST http://localhost:5001/api/ml_anomaly/refresh
```

## File Upload

### POST /upload

Upload a CSV traffic file. Replaces existing data and triggers full analysis.

```bash
curl -X POST -F "file=@traffic.csv" http://localhost:5001/upload
```

**CSV Format:**

```
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
2025-12-01 08:00:15,192.168.1.100,8.8.8.8,52341,53,UDP,256,DNS,student_001
```

## Realtime Endpoints

### POST /api/realtime/start

Start traffic replay. Optional JSON body with `rate` (events/second) and `loop` (boolean).

```bash
curl -X POST http://localhost:5001/api/realtime/start \
  -H "Content-Type: application/json" \
  -d '{"rate": 5, "loop": true}'
```

### POST /api/realtime/stop

Stop traffic replay.

```bash
curl -X POST http://localhost:5001/api/realtime/stop
```

### POST /api/realtime/rate

Adjust replay rate on the fly.

```bash
curl -X POST http://localhost:5001/api/realtime/rate \
  -H "Content-Type: application/json" \
  -d '{"rate": 10}'
```

### GET /api/realtime/status

Query current replay status and live metrics.

```bash
curl http://localhost:5001/api/realtime/status
```

### GET /api/realtime/stream

SSE event stream for real-time dashboard. Pushes `snapshot`, `event`, `metrics`, `alert`, and `finished` events.

## Error Responses

All endpoints return 404 with JSON when no data is loaded:

```json
{
  "error": "no_data",
  "message": "请先上传 CSV 流量数据。"
}
```
