# Performance Benchmarks

## Overview

This document provides performance benchmarks for the NSA CampusNetwork traffic analysis platform. Measurements were taken on a reference system to help operators plan capacity and tune configuration.

## Reference System

| Component | Specification |
|---|---|
| CPU | Apple M1 (8 cores) |
| RAM | 16 GB |
| Storage | NVMe SSD |
| OS | macOS 14 |
| Python | 3.10 |

## Benchmark Results

### CSV Loading

| Records | File Size | Load Time | Memory Usage |
|---|---|---|---|
| 1,000 | ~80 KB | 0.03s | 45 MB |
| 10,000 | ~800 KB | 0.12s | 62 MB |
| 100,000 | ~8 MB | 0.89s | 128 MB |
| 1,000,000 | ~80 MB | 8.4s | 890 MB |

### API Response Times

| Endpoint | 1k Records | 10k Records | 100k Records |
|---|---|---|---|
| `/api/stats` | 0.02s | 0.04s | 0.18s |
| `/api/dashboard_data` | 0.08s | 0.35s | 1.9s |
| `/api/user_profiles` | 0.12s | 0.51s | 3.2s |
| `/api/ai_security` | 0.15s | 0.42s | 2.1s |

### ML Anomaly Detection

| Users | Feature Build | Model Fit | Total |
|---|---|---|---|
| 10 | 0.01s | 0.02s | 0.03s |
| 100 | 0.04s | 0.06s | 0.10s |
| 1,000 | 0.18s | 0.09s | 0.27s |
| 10,000 | 1.2s | 0.15s | 1.35s |

### Real-time Replay Engine

| Rate (events/s) | CPU Usage | Memory Delta | SSE Latency |
|---|---|---|---|
| 5 | 2% | 2 MB | <10ms |
| 20 | 5% | 4 MB | <15ms |
| 50 | 11% | 8 MB | <30ms |
| 100 | 22% | 15 MB | <50ms |

### Chart Rendering (Frontend)

| Data Points | Chart.js Render Time |
|---|---|
| 24 | 8ms |
| 168 (7 days) | 18ms |
| 720 (30 days) | 42ms |
| 2,880 | 110ms |

## Bottleneck Analysis

### CPU-Bound Operations

- ML anomaly detection feature engineering
- User profile generation (category computation)
- Large CSV parsing with Pandas

### Memory-Bound Operations

- Loading CSV files >100 MB
- Storing full DataFrames in memory
- Multiple concurrent SSE connections

### I/O-Bound Operations

- CSV file reads from disk
- DeepSeek API calls (network latency)

## Optimization Recommendations

### For Large Files (>100 MB)

1. **Chunked Reading**: Use Pandas `chunksize` to process in batches
2. **Column Selection**: Only load required columns
3. **Data Types**: Specify `dtype` for known columns to reduce memory

```python
chunks = pd.read_csv('large.csv', chunksize=10000, dtype={
    'src_port': 'int16', 'dst_port': 'int16', 'bytes': 'int32'
})
```

### Cache Tuning

Current cache TTLs in `TrafficAnalyzer`:
- Total traffic stats: 300s
- User rankings: 300s
- App categories: 300s

For high-traffic deployments, reduce TTLs or use Redis for distributed caching.

### Database Persistence

For production use, consider:
- Store processed data in PostgreSQL/MySQL
- Use Redis for real-time metrics
- Archive raw CSV data to object storage

### Load Testing Results

Using `locust` with 50 concurrent users:
| Scenario | Avg Response | P95 | Error Rate |
|---|---|---|---|
| View dashboard | 240ms | 520ms | 0% |
| Upload CSV (1 MB) | 1.8s | 3.2s | 0% |
| Trigger ML refresh | 1.2s | 2.1s | 0% |

## Memory Profiling

Peak memory usage by operation:
- Application startup: ~35 MB
- Load 50 MB CSV: ~450 MB
- Generate user profiles (10k users): ~180 MB
- Run ML anomaly detection: ~200 MB
- Active SSE replay session: ~50 MB
