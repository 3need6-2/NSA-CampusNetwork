# Security Considerations

## Overview

This document outlines security considerations for deploying and operating the NSA CampusNetwork traffic analysis platform in production environments.

## Deployment Security

### Production Server

Never use Flask's development server (`debug=True`) in production. Use a production WSGI server:

- Gunicorn (Linux/macOS)
- Waitress (cross-platform)
- uWSGI

Example Gunicorn deployment:
```bash
gunicorn -w 4 -b 0.0.0.0:5001 app:app
```

### Reverse Proxy

Place the application behind a reverse proxy (Nginx, Caddy, Traefik) to handle:
- TLS termination
- Rate limiting
- Request filtering
- DDoS protection

## Data Privacy

### Traffic Data

- CSV files contain user identifiers (`user` column), IP addresses, and traffic metadata
- Data is stored locally in `data/traffic.csv` on the server filesystem
- Consider data retention policies for uploaded files
- Implement access controls to prevent unauthorized data access

### User Identifiers

- User IDs (`student_001`, etc.) may be considered Personally Identifiable Information (PII)
- Consider pseudonymization or hashing before storage
- Limit exposure in API responses and frontend displays

## API Security

### Authentication

The application currently does not implement authentication. For production:
- Add authentication middleware (OAuth2, JWT, or session-based)
- Restrict upload endpoints to authorized users
- Protect admin-only operations

### Input Validation

All API endpoints validate parameters before processing. Key checks include:
- File type validation (CSV only)
- File size limits (50 MB max)
- Timestamp format validation
- Numeric bounds checking for ports and bytes

### Rate Limiting

Consider implementing rate limiting on:
- File upload endpoints
- DeepSeek API review calls
- Real-time replay API

## Network Security

### SSE (Server-Sent Events)

The real-time dashboard uses SSE for event streaming. Considerations:
- SSE connections are long-lived; configure appropriate timeouts
- Avoid exposing SSE endpoints without authentication in production
- SSE does not support binary data; all payloads are JSON

### API Endpoints

| Endpoint | Risk | Mitigation |
|---|---|---|
| `/upload` | File upload vector | Validate content, limit size, check CSV structure |
| `/api/realtime/start` | Resource consumption | Rate limit, require auth |
| `/api/ai_security/deepseek` | External API call | Validate input, set timeouts |

## Third-Party Dependencies

### CDN Resources

The application loads Chart.js from CDN:
- dashboard.html loads Chart.js 3.9.1 from `cdn.jsdelivr.net`
- realtime.html loads Chart.js 4.4.1 from `cdn.jsdelivr.net`

For air-gapped environments, vendor these libraries locally.

### DeepSeek API

- Optional integration sends summarized risk evidence only
- Raw traffic data is never transmitted to DeepSeek
- Configure API key via environment variable (`DEEPSEEK_API_KEY`)
- Set appropriate timeouts (default 20s)

## AI Security Module

The `utils/ai_security.py` module implements defensive security analysis:

- Detects port scanning patterns
- Identifies sensitive service access
- Flags anomalous traffic volumes
- Recognizes AI-assisted attack patterns
- Does NOT implement offensive capabilities

### DeepSeek Review

- Only summarized risk metadata is sent for review
- Full traffic payloads are never transmitted
- API key should be stored securely (environment variable, not in code)

## ML Anomaly Detection

The IsolationForest model (utils/ml_anomaly.py) operates entirely locally:
- No data leaves the server
- Feature vectors are computed from traffic aggregates
- Model parameters are tunable via `config.yaml`

## File System Security

- Uploaded files are stored with a fixed name (`traffic.csv`)
- Ensure the `data/` directory has appropriate permissions
- Regularly audit file sizes and disk usage

## Logging

Logging configuration in `utils/logging_config.py`:
- Logs contain operational information
- Avoid logging sensitive data (passwords, API keys, raw traffic)
- Consider log rotation for production deployments

## Recommendations

1. Enable HTTPS in production
2. Add authentication before deploying publicly
3. Regularly update dependencies (`pip-audit` or `safety` check)
4. Monitor server resource usage (CPU, memory, disk)
5. Implement backup strategy for `data/` directory
6. Review and update `SECURITY.md` for vulnerability reporting
7. Use environment variables for all secrets
8. Consider containerization with read-only root filesystem
