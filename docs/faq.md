# Frequently Asked Questions

## General

### What is NSA-CampusNetwork?

A campus network traffic analysis and security visualization system. It processes network traffic data (CSV format) to generate statistics, user behavior profiles, security threat detection, and real-time situational awareness dashboards.

### Who is this project for?

Network administrators, security analysts, and researchers who need to monitor campus network traffic, detect anomalies, and understand user behavior patterns.

### Is this a real security tool?

It is a demonstration and analysis tool. The AI security audit and ML anomaly detection provide useful insights, but should not be used as a sole security measure in production environments without proper validation.

## Data & CSV

### What format does the CSV need to be?

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,app_category,user
```

### What is the maximum file size?

50 MB by default. This can be changed in `config.yaml` under `upload.max_size_mb`.

### How many records can I upload?

There is no hard limit on record count, but performance depends on your system's memory. For production, consider using database persistence.

### Does the system support incremental uploads?

Not currently. Each upload replaces the existing CSV and triggers a full re-analysis.

## Features

### How does user profiling work?

The `UserProfileAnalyzer` processes traffic records per user and generates tags based on application usage, activity time patterns, and security-related behaviors. Tags include categories like "Video Heavy", "Night Owl", and "Suspicious Scanner".

### What ML algorithm is used for anomaly detection?

IsolationForest from scikit-learn. It identifies users whose traffic patterns deviate from the norm.

### Can I use DeepSeek without an API key?

Yes. DeepSeek review is optional. The local AI security rules engine runs independently and provides comprehensive results without any external API calls.

### What is the real-time dashboard?

An SSE-powered feature that replays your CSV data at a configurable rate, simulating live traffic with real-time curves, event streams, and alert feeds.

## Technical

### What port does the application use?

5001 by default. Configure via `FLASK_PORT` environment variable or `config.yaml`.

### Can I run this behind a reverse proxy?

Yes. See the deployment guide for Nginx configuration, especially SSE-specific proxy settings.

### Does it support HTTPS?

Not directly. Use a reverse proxy (Nginx, Caddy) with TLS termination in production.

### How do I reset all data?

```bash
rm -f data/traffic.csv data/user_profiles.json
python app.py  # Starts fresh
```

### Is there an API for external tools?

Yes. See `docs/api.md` for the full API reference.

## Troubleshooting

### Why are my charts not rendering?

Most likely the Chart.js CDN is blocked. Check network connectivity and browser console for errors.

### Why is ML anomaly detection returning no results?

The module requires at least 5 unique users in the dataset. Add more users to your CSV data.

### Can I contribute features?

Absolutely. See `CONTRIBUTING.md` for guidelines.

## Roadmap

### Will there be database support?

Database persistence is on the roadmap for future releases to support historical queries and larger datasets.

### Is multi-tenancy planned?

Role-based access control and multi-tenant support are under consideration for future versions.

### Will there be a REST API SDK?

An API client SDK is planned to make integration with external monitoring systems easier.

## License

### What license is this project under?

MIT License. See `LICENSE` for details.

### Can I use this commercially?

Yes, subject to the terms of the MIT License.
