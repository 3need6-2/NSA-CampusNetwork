# Roadmap

## Overview

This document outlines the planned development方向和 feature priorities for NSA-CampusNetwork.

## Short-Term (Next 3 Months)

- [ ] **Database persistence**: Replace CSV file storage with SQLite/PostgreSQL for historical queries and incremental data ingestion
- [ ] **User authentication**: Add login system with role-based access control (admin, analyst, viewer)
- [ ] **Multi-file support**: Allow uploading and switching between multiple traffic datasets
- [ ] **Export enhancements**: Add PDF report generation for security audit summaries
- [ ] **Notification system**: Email/webhook alerts for high-severity security events
- [ ] **Improved ML models**: Add One-Class SVM and LOF alongside IsolationForest for ensemble anomaly detection

## Medium-Term (3-6 Months)

- [ ] **Real network integration**: Support live packet capture via pcap/NetFlow integration
- [ ] **Time-series analysis**: Add trend forecasting using ARIMA or Prophet for traffic prediction
- [ ] **Geolocation mapping**: IP-to-location enrichment for visual attack source mapping
- [ ] **Custom dashboard builder**: User-configurable dashboard widgets and layouts
- [ ] **Alert history**: Persistent alert storage with search and filtering
- [ ] **API authentication**: API key management for external tool integration
- [ ] **Internationalization**: Support for multiple languages (中文, English, 日本語)

## Long-Term (6-12 Months)

- [ ] **Distributed deployment**: Horizontal scaling with Redis-based session and state management
- [ ] **Real-time packet processing**: Integrate with Kafka/Pulsar for streaming traffic analysis
- [ ] **Machine learning pipeline**: Automated model retraining with feedback loop
- [ ] **Mobile app**: Companion mobile application for monitoring on-the-go
- [ ] **SIEM integration**: Support for Syslog, Splunk HEC, and Elasticsearch output
- [ ] **Plugin system**: Community-contributed analysis modules and security rules
- [ ] **Cloud deployment**: One-click deploy to AWS/GCP/Azure with managed services

## Completed Features

- [x] CSV-based traffic analysis with basic statistics
- [x] User profiling with automatic tag generation
- [x] Local AI security audit rules engine
- [x] DeepSeek API integration for secondary review
- [x] IsolationForest-based ML anomaly detection
- [x] Real-time situational awareness dashboard with SSE
- [x] Docker support with docker-compose
- [x] Prometheus-style metrics endpoint
- [x] Rate limiting on upload endpoint
- [x] Caching for dashboard and profile APIs
- [x] Comprehensive test suite

## How to Contribute

See `CONTRIBUTING.md` for guidelines. Feature requests and bug reports are welcome via GitHub Issues.
