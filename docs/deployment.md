# Deployment Guide

## Docker Deployment

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 1.29+ (or Docker Compose v2)

### Quick Start with Docker Compose

```bash
# Clone the repository
git clone https://github.com/Arbeiter-bit/NSA-CampusNetwork.git
cd NSA-CampusNetwork

# Build and start
docker-compose up --build -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

The application is available at `http://localhost:5001`.

### Manual Docker Build

```bash
docker build -t nsa-campus-network .
docker run -d -p 5001:5001 --name nsa-campus -v $(pwd)/data:/app/data nsa-campus-network
```

## Production Deployment

### WSGI Server

Flask's development server is not suitable for production. Use Gunicorn or Waitress:

```bash
# Install production server
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:5001 app:app
```

### Environment Variables

| Variable            | Description                | Default                      |
| ------------------- | -------------------------- | ---------------------------- |
| `FLASK_SECRET_KEY`  | Flask session secret key   | Auto-generated dev key       |
| `DEEPSEEK_API_KEY`  | DeepSeek API key           | (optional)                   |
| `DEEPSEEK_BASE_URL` | DeepSeek API base URL      | `https://api.deepseek.com`   |
| `DEEPSEEK_MODEL`    | DeepSeek model name        | `deepseek-chat`              |
| `DEEPSEEK_TIMEOUT`  | DeepSeek request timeout   | `20`                         |

### Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/realtime/stream {
        proxy_pass http://127.0.0.1:5001;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        chunked_transfer_encoding on;
    }
}
```

### Security Checklist

- [ ] Set `FLASK_SECRET_KEY` to a strong random value
- [ ] Disable `debug=True` in production
- [ ] Configure proper authentication for upload and admin endpoints
- [ ] Set `MAX_CONTENT_LENGTH` to appropriate file size limit
- [ ] Use HTTPS with a valid TLS certificate
- [ ] Restrict access to DeepSeek review endpoint if not needed
- [ ] Regularly update dependencies

## Data Persistence

Traffic data and user profiles are stored in the `data/` directory. Mount this directory as a volume when using Docker to persist data across restarts.

```bash
docker run -d -p 5001:5001 -v /path/to/data:/app/data nsa-campus-network
```

## Troubleshooting

### Application won't start

Check that all dependencies are installed and the `data/` directory exists.

### CSV upload fails

Verify the CSV format matches the expected columns and the file size is under 50 MB.

### Real-time dashboard shows no events

Ensure data is loaded (visit home page or `/dashboard` first), then click "Start Replay" on the realtime page.
