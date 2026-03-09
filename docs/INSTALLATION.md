# Installation & Deployment Guide

## Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Git
- API keys for threat intelligence sources

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/threat-intel-automation.git
cd threat-intel-automation

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install package
pip install -e .

# 5. Create configuration
cp config/config.example.yaml config/config.yaml

# 6. Edit configuration with your API keys
nano config/config.yaml
```

### Getting API Keys

#### AlienVault OTX (Free)
1. Visit https://otx.alienvault.com/
2. Create free account
3. Go to Settings → API Integration
4. Copy your API key

#### AbuseIPDB (Free Tier Available)
1. Visit https://www.abuseipdb.com/
2. Register for free account
3. Go to Account → API
4. Generate API key (v2)

#### MISP (Optional - Requires Instance)
- Deploy your own: https://www.misp-project.org/
- Or get access to community instance
- Generate API key from user settings

### First Run

```bash
# Test basic collection
python examples/basic_collection.py

# Run full pipeline
python main.py

# Run with custom config
python main.py --config config/custom.yaml
```

## Detailed Installation

### System Requirements

**Minimum:**
- 2 CPU cores
- 4GB RAM
- 10GB disk space
- Python 3.8+

**Recommended:**
- 4 CPU cores
- 8GB RAM
- 50GB disk space (for logs and cache)
- Python 3.10+

### Dependencies

Install all dependencies:
```bash
pip install -r requirements.txt
```

Core dependencies:
- `requests` - HTTP client
- `pyyaml` - Configuration parsing
- `pandas` - Data processing
- `stix2` - STIX format support

Optional dependencies for SIEM integration:
```bash
# For Elasticsearch
pip install elasticsearch

# For Splunk SDK
pip install splunk-sdk

# For all optional features
pip install -r requirements.txt
```

### Configuration

#### Basic Configuration

Edit `config/config.yaml`:

```yaml
# Set your API keys
sources:
  alienvault_otx:
    enabled: true
    api_key: "your_otx_key_here"
  
  abuseipdb:
    enabled: true
    api_key: "your_abuseipdb_key_here"

# Configure processing
processing:
  min_confidence: 70
  max_false_positive_rate: 0.15
  staleness_days: 90
```

#### SIEM Integration

For Splunk:
```yaml
siem:
  splunk:
    enabled: true
    url: "https://splunk.example.com:8088/services/collector"
    token: "your_hec_token"
    index: "threat_intel"
```

For Elasticsearch:
```yaml
siem:
  elastic:
    enabled: true
    hosts: ["https://elastic.example.com:9200"]
    api_key: "your_elastic_api_key"
    index: "threat-intel"
```

### Environment Variables

Alternatively, set configuration via environment variables:

```bash
export OTX_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export SPLUNK_HEC_TOKEN="your_token"
```

## Deployment Options

### Option 1: Standalone Script

Run manually or via cron:

```bash
# Run immediately
python main.py

# Schedule with cron (every hour)
crontab -e
# Add: 0 * * * * cd /path/to/threat-intel-automation && /path/to/venv/bin/python main.py
```

### Option 2: Systemd Service (Linux)

Create service file `/etc/systemd/system/threat-intel.service`:

```ini
[Unit]
Description=Threat Intelligence Automation
After=network.target

[Service]
Type=simple
User=threat-intel
WorkingDirectory=/opt/threat-intel-automation
ExecStart=/opt/threat-intel-automation/venv/bin/python /opt/threat-intel-automation/main.py
Restart=on-failure
RestartSec=300

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable threat-intel
sudo systemctl start threat-intel
```

### Option 3: Docker Container

Build container:
```bash
docker build -t threat-intel-automation .
```

Run container:
```bash
docker run -d \
  --name threat-intel \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/output:/app/output \
  -e OTX_API_KEY="your_key" \
  -e ABUSEIPDB_API_KEY="your_key" \
  threat-intel-automation
```

### Option 4: Kubernetes Deployment

Deploy to Kubernetes:
```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/cronjob.yaml
```

## Production Deployment

### Security Considerations

1. **API Key Management**
   - Use environment variables or secrets management
   - Never commit API keys to version control
   - Rotate keys regularly

2. **Network Security**
   - Use firewall rules to restrict outbound connections
   - Enable SSL verification
   - Use proxy for internet access

3. **Access Control**
   - Run with dedicated service account
   - Limit file system permissions
   - Implement least privilege

### High Availability

For production environments:

1. **Database Backend** (Optional)
   - Use Redis for caching
   - PostgreSQL for persistent storage
   - Elasticsearch for search

2. **Load Balancing**
   - Multiple collector instances
   - Shared message queue (RabbitMQ/Kafka)
   - Distributed caching

3. **Monitoring**
   - Prometheus metrics
   - Grafana dashboards
   - Alert on collection failures

### Logging

Configure logging:

```yaml
logging:
  file: "logs/threat_intel.log"
  max_bytes: 10485760  # 10MB
  backup_count: 5
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

Log rotation with logrotate:
```
/opt/threat-intel-automation/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
```

### Performance Tuning

1. **Parallel Collection**
   ```yaml
   performance:
     max_workers: 4  # Number of parallel threads
   ```

2. **Caching**
   ```yaml
   general:
     cache_enabled: true
     cache_ttl: 3600  # 1 hour
   ```

3. **Batch Processing**
   ```yaml
   siem:
     splunk:
       batch_size: 100  # Events per batch
   ```

## Troubleshooting

### Common Issues

**Issue: ImportError for elasticsearch**
```bash
Solution: pip install elasticsearch>=8.0.0
```

**Issue: SSL Certificate Verification Failed**
```yaml
Solution: Set verify_ssl: false in config (not recommended for production)
```

**Issue: API Rate Limit Exceeded**
```yaml
Solution: Increase rate_limit_delay in source configuration
```

**Issue: Permission Denied on Log Files**
```bash
Solution: sudo chown -R threat-intel:threat-intel /opt/threat-intel-automation
```

### Debug Mode

Enable debug logging:
```bash
python main.py --config config/config.yaml
# Edit config.yaml: general.log_level: DEBUG
```

### Testing Connection

Test SIEM connections:
```python
from threat_intel.integrations.splunk_connector import SplunkConnector

config = {'url': '...', 'token': '...'}
splunk = SplunkConnector(config)
print(splunk.test_connection())
```

## Updating

Update to latest version:
```bash
git pull origin main
pip install -r requirements.txt --upgrade
python main.py
```

## Uninstallation

Remove installation:
```bash
# Deactivate virtual environment
deactivate

# Remove directory
rm -rf threat-intel-automation

# Remove systemd service (if installed)
sudo systemctl stop threat-intel
sudo systemctl disable threat-intel
sudo rm /etc/systemd/system/threat-intel.service
```

## Support

- Documentation: `/docs`
- Issues: https://github.com/yourusername/threat-intel-automation/issues
- Email: your.email@university.edu
