# Troubleshooting Guide

## Installation Issues

### Module Import Errors

```
ModuleNotFoundError: No module named 'flask'
```

**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```
Ensure your virtual environment is activated.

### Pandas Parsing Errors

```
ValueError: could not convert string to float
```

**Solution:** Check that `bytes`, `src_port`, `dst_port` columns contain only numeric values.

## Runtime Issues

### Application Fails to Start

**Symptoms:**
- Port already in use
- Missing data directory
- Dependency conflicts

**Solutions:**
```bash
# Check if port 5001 is in use
lsof -i :5001

# Create data directory
mkdir -p data

# Check Python version
python --version  # Must be >= 3.8
```

### CSV Upload Fails

**Common causes:**
1. Missing required columns
2. File exceeds 50 MB limit
3. Incorrect file format (must be `.csv`)

**Verify CSV:**
```bash
python -c "
import pandas as pd
df = pd.read_csv('data/traffic.csv')
print(df.columns.tolist())
print(df.dtypes)
print(f'Rows: {len(df)}')
"
```

Required columns: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, `app_category`, `user`

### Charts Not Displaying

**Checklist:**
1. CSV file is loaded (visit home page and confirm stats are shown)
2. Browser console has no JavaScript errors
3. Internet connection allows loading Chart.js from CDN
4. Flask server is running on port 5001

### Dashboard Shows "No Data"

**Solutions:**
- Upload a valid CSV file via the home page
- Ensure `data/traffic.csv` exists
- Check the CSV has at least one data row
- Restart the Flask application

## Module-Specific Issues

### DeepSeek Review Not Working

```bash
# Verify API key is set
echo $DEEPSEEK_API_KEY

# Test the API endpoint
curl -X POST http://localhost:5001/api/ai_security/deepseek
```

**Solutions:**
- Set `DEEPSEEK_API_KEY` environment variable
- Check network access to `https://api.deepseek.com`
- Verify the model name matches DeepSeek's current API offerings
- DeepSeek review is optional; local AI security runs without it

### ML Anomaly Detection Returns Empty

The module requires at least 5 users to run. If your CSV has fewer than 5 unique users, the detection is skipped.

**Check:**
```bash
python -c "
import pandas as pd
df = pd.read_csv('data/traffic.csv')
print(f'Unique users: {df[\"user\"].nunique()}')
"
```

### Real-Time Dashboard Shows No Events

**Troubleshooting steps:**
1. Confirm data is loaded (visit `/dashboard` first)
2. Click "Start Replay" button on the real-time page
3. Check replay status: `curl http://localhost:5001/api/realtime/status`
4. Verify the CSV has at least one row of data
5. Ensure browser supports SSE (EventSource API)

## Performance Issues

### Slow Dashboard Loading

- Large CSV files (>100MB) may cause slow analysis
- Consider using smaller sample data for testing
- Production deployments should use a proper WSGI server (Gunicorn, Waitress)
- Enable caching by ensuring the cache module is functioning

### High Memory Usage

- Check CSV file size (limit: 50MB upload)
- Monitor with `/api/metrics` endpoint
- Restart the application between large file uploads
- Consider database persistence for production use

## Deployment Issues

### Docker Build Fails

```bash
# Clear Docker cache
docker-compose build --no-cache

# Check Docker version
docker --version  # Requires 20.10+
docker-compose --version  # Requires 1.29+
```

### Production Server Issues

- Flask debug mode must be `false`
- Use environment variables for secrets, never hardcode
- Configure proper reverse proxy for SSE buffering:
  ```nginx
  location /api/realtime/stream {
      proxy_buffering off;
      proxy_cache off;
  }
  ```

## Getting Help

If the above steps do not resolve your issue:
1. Check open/closed issues on GitHub
2. Open a new issue with:
   - Python version: `python --version`
   - OS details
   - Full error traceback
   - Steps to reproduce
   - Sample CSV (if applicable)
