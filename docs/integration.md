# Integration Guide

## Overview

This document describes how to integrate the NSA CampusNetwork system with other tools, platforms, and data pipelines.

## API Integration

### REST API

All API endpoints return JSON responses suitable for integration with external systems.

#### Basic Stats Endpoint

```bash
curl http://localhost:5001/api/stats
```

Response includes total traffic, user rankings, app categories, and active hours.

#### Dashboard Data

```bash
curl http://localhost:5001/api/dashboard_data
```

Returns a complete data payload including traffic stats, ML anomalies, AI security review, and user profiles.

#### Export

```bash
curl http://localhost:5001/api/export/json -o export.json
```

Downloads all current analysis data as a JSON bundle.

### SSE Integration

The real-time stream at `/api/realtime/stream` uses Server-Sent Events. Connect from any SSE-compatible client:

```javascript
const evtSource = new EventSource('http://localhost:5001/api/realtime/stream');
evtSource.addEventListener('event', (e) => {
    const data = JSON.parse(e.data);
    // Process real-time traffic event
});
evtSource.addEventListener('alert', (e) => {
    const alert = JSON.parse(e.data);
    // Forward alert to external SIEM
});
evtSource.addEventListener('metrics', (e) => {
    const metrics = JSON.parse(e.data);
    // Push to monitoring system
});
```

## External System Integration

### SIEM Integration

Forward alerts to SIEM systems (Splunk, ELK, QRadar):

```python
import requests
import json

def forward_to_siem(alert):
    payload = {
        "source": "NSA-CampusNetwork",
        "type": "traffic_alert",
        "severity": alert["level"],
        "title": alert["title"],
        "entity": alert["entity"],
        "timestamp": alert["ts"],
        "detail": alert["detail"]
    }
    requests.post("https://siem.internal/events", json=payload)
```

### Prometheus Metrics

Expose metrics for Prometheus scraping via the `utils/metrics.py` module:

```python
from utils.metrics import MetricsCollector

metrics = MetricsCollector()
metrics.record_upload(1024000)
metrics.record_anomaly_detection(0.35)
```

Access metrics at a dedicated endpoint (add to `app.py`):

```python
@app.route('/metrics')
def prometheus_metrics():
    return metrics_collector.export(), 200, {'Content-Type': 'text/plain'}
```

### Webhook Notifications

Configure webhooks for critical alerts by adding a webhook URL to `config.yaml`:

```yaml
webhooks:
  - url: "https://hooks.slack.com/services/xxx/yyy/zzz"
    events: ["alert.critical", "alert.high"]
    format: "slack"
```

### Database Export

Processed data can be exported to databases for long-term storage:

```sql
-- PostgreSQL schema example
CREATE TABLE traffic_records (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL,
    src_ip INET,
    dst_ip INET,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR(10),
    bytes BIGINT,
    app_category VARCHAR(50),
    user_id VARCHAR(50)
);
```

### File System Integration

The system monitors `data/traffic.csv` for changes. Automate data ingestion:

```bash
# Cron job: copy data from external source
cp /shared/network/traffic_latest.csv /path/to/NSA-CampusNetwork/data/traffic.csv

# Then trigger reload via API
curl -X POST http://localhost:5001/api/reload
```

## Docker Integration

### Docker Compose

The included `docker-compose.yml` supports multi-service deployment:

```bash
docker-compose up -d
```

### Kubernetes

Sample Kubernetes manifest:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nsa-campusnetwork
spec:
  replicas: 2
  selector:
    matchLabels:
      app: nsa-campusnetwork
  template:
    metadata:
      labels:
        app: nsa-campusnetwork
    spec:
      containers:
      - name: app
        image: nsa-campusnetwork:latest
        ports:
        - containerPort: 5001
        env:
        - name: FLASK_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: app-secrets
              key: flask-secret-key
```

## CI/CD Integration

### GitHub Actions

The project includes GitHub Actions workflows for CI. Extend to deploy:

```yaml
deploy:
  needs: build
  runs-on: ubuntu-latest
  steps:
    - uses: actions/download-artifact@v4
    - name: Deploy to server
      run: |
        scp dist/* user@server:/opt/nsa-campusnetwork/
        ssh user@server 'systemctl restart nsa-campusnetwork'
```

## Data Pipeline Integration

### Apache Kafka

Stream traffic events to Kafka topics:

```python
from kafka import KafkaProducer

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])

def publish_event(event):
    producer.send('campus-traffic', json.dumps(event).encode('utf-8'))
```

### Filebeat / Logstash

Configure Filebeat to monitor the application log file:

```yaml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/nsa-campusnetwork/*.log
output.elasticsearch:
  hosts: ["localhost:9200"]
```

## Monitoring Integration

### Health Check

```bash
curl http://localhost:5001/api/health
```

Response: `{"status": "ok", "timestamp": "..."}`

### Custom Grafana Dashboard

Query the `/api/stats` endpoint from a Grafana JSON datasource to build custom dashboards for traffic trends, user activity, and security alerts.
