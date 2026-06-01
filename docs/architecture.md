# System Architecture

## Overview

NSA-CampusNetwork is a Flask-based web application for campus network traffic analysis, user profiling, AI security auditing, ML anomaly detection, and real-time situational awareness.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Client Browser                                 │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────────────────┐   │
│  │ index.html│  │ dashboard.html│  │ realtime.html (SSE EventSource)   │   │
│  └─────┬────┘  └──────┬───────┘  └──────────────┬─────────────────────┘   │
│        │              │                          │                         │
└────────┼──────────────┼──────────────────────────┼─────────────────────────┘
         │              │                          │
         ▼              ▼                          ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                         Flask Web Server (app.py)                          │
│                                                                             │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────────────┐   │
│  │   Routes     │  │ AnalyzerState     │  │  Flask-Limiter             │   │
│  │   /api/*     │  │ (Thread-safe      │  │  Rate Limiting             │   │
│  │   /          │  │  global state)    │  │                            │   │
│  │   /dashboard │  │                  │  │                            │   │
│  │   /realtime  │  │                  │  │                            │   │
│  └──────┬───────┘  └────────┬─────────┘  └────────────────────────────┘   │
└─────────┼───────────────────┼──────────────────────────────────────────────┘
          │                   │
          ▼                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                            Application Layer                                │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐   │
│  │  utils/analysis  │  │ utils/user_     │  │  utils/ai_security.py    │   │
│  │  .py             │  │ profile.py      │  │                          │   │
│  │  TrafficAnalyzer │  │ UserProfile     │  │  AISecurityAnalyzer      │   │
│  │  Chart Generators│  │ Analyzer        │  │  Local Rules Engine      │   │
│  └────────┬────────┘  └───────┬─────────┘  │  DeepSeek API Client     │   │
│           │                   │            └───────────┬──────────────┘   │
│           ▼                   ▼                        ▼                   │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────────────────┐   │
│  │  utils/ml_       │  │ utils/realtime  │  │  utils/                  │   │
│  │  anomaly.py      │  │ .py             │  │  constants.py            │   │
│  │  IsolationForest │  │ ReplayEngine    │  │  cache.py                │   │
│  │  Anomaly Scoring │  │ SSE Stream      │  │  metrics.py              │   │
│  └────────┬────────┘  └───────┬─────────┘  │  response.py             │   │
│           │                   │            └──────────────────────────┘   │
└───────────┼───────────────────┼────────────────────────────────────────────┘
            │                   │
            ▼                   ▼
┌────────────────────────────────────────────────────────────────────────────┐
│                              Data Layer                                     │
│                                                                             │
│  ┌───────────────────────┐  ┌─────────────────────────────────────────┐   │
│  │    data/traffic.csv    │  │    data/user_profiles.json              │   │
│  │    (Traffic Records)   │  │    (Generated User Profiles)            │   │
│  └───────────────────────┘  └─────────────────────────────────────────┘   │
│                                                                             │
│  ┌───────────────────────┐  ┌─────────────────────────────────────────┐   │
│  │    config.yaml         │  │    .env / .env.example                  │   │
│  │    (App Configuration) │  │    (Environment Variables)              │   │
│  └───────────────────────┘  └─────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Module Interaction Flow

### Data Upload & Analysis Pipeline

```
User Uploads CSV → /upload route → Pandas validation → TrafficAnalyzer
                                                          │
                                    ┌─────────────────────┼─────────────────────┐
                                    ▼                     ▼                     ▼
                              UserProfileAnalyzer   AISecurityAnalyzer    detect_anomalies
                                    │                     │                     │
                                    ▼                     ▼                     ▼
                           data/user_profiles.json   AI Security Report    ML Anomaly Report
                                                                               │
                                    └─────────────────────┼─────────────────────┘
                                                          ▼
                                                  AnalyzerState
                                                  (shared state)
```

### Request Flow (Dashboard)

```
Browser → GET /dashboard → app.py (dashboard route) → AnalyzerState.snapshot()
                                                          │
                                    ┌─────────────────────┼─────────────────────┐
                                    ▼                     ▼                     ▼
                              TrafficAnalyzer         AI Security           ML Anomaly
                              .get_total_traffic()     Report                Report
                              .get_user_ranking()
                              .get_app_category()
                              .get_active_hours()
                                    │
                                    ▼
                              render_template(dashboard.html, ...)
                                    │
                                    ▼
                              Chart.js renders charts in browser
```

### Real-time SSE Flow

```
Browser                    Flask Server                    ReplayEngine
   │                          │                                │
   │── GET /realtime ────────►│                                │
   │◄── render template ─────┤                                │
   │                          │                                │
   │── GET /api/realtime/ ───►│── POST /start ───────────────►│
   │   stream (SSE)           │                                │── Reads CSV rows
   │                          │                                │── Timer loop
   │◄── event: snapshot ─────┤◄────── yield events ──────────┤
   │◄── event: event ────────┤                                │
   │◄── event: metrics ──────┤                                │
   │◄── event: alert ────────┤                                │
   │◄── event: finished ─────┤                                │
```

## Key Design Decisions

- **Thread-safe state**: `AnalyzerState` uses `threading.RLock` for safe concurrent access
- **SSE for realtime**: Server-Sent Events instead of WebSocket for simpler server-side implementation
- **Optional DeepSeek**: External AI review is opt-in; local rules run independently
- **Caching**: Dashboard data cached for 60s, user profiles for 120s to reduce recomputation
- **Layered detection**: Rules engine → ML (IsolationForest) → optional DeepSeek review for defense in depth
