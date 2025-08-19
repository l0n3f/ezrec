# ezrec Usage Examples

This document provides practical examples of using ezrec for bug bounty reconnaissance.

## Basic Usage

### Single Domain Reconnaissance

```bash
# Basic subdomain enumeration and host probing
ezrec recon --domain example.com --subdomains --httpx

# Full pipeline on a single domain
ezrec recon --domain example.com --subdomains --httpx --crawl --endpoints --xss --nuclei --ffuf
```

### Multiple Domains from File

```bash
# Create a file with target domains
echo -e "example.com\ntest.example.com\napi.example.com" > targets.txt

# Run reconnaissance on all targets
ezrec recon --seed-file targets.txt --subdomains --httpx --crawl
```

## Program-Specific Configuration

### Create a Program Profile

```bash
# Create a profile for a specific bug bounty program
mkdir -p profiles
cat > profiles/hackerone.yml << EOF
program: "hackerone"
rate: 3
concurrency: 30
timeout: 45s

headers:
  User-Agent: "ezrec/1.0 (HackerOne Bug Bounty Research)"
  X-Bug-Bounty-Platform: "hackerone"

scope:
  include:
    - ".*\\.hackerone\\.com$"
    - ".*\\.example\\.com$"
  exclude:
    - ".*\\.staging\\..*"
    - ".*\\.dev\\..*"
EOF

# Use the program profile
ezrec recon --program hackerone --seed-file targets.txt --subdomains --httpx --crawl
```

## Advanced Features

### XSS Testing with AI

```bash
# Basic XSS testing
ezrec recon --domain example.com --httpx --crawl --xss --payload "<script>alert(1)</script>"

# XSS testing with AI-powered payload suggestions
ezrec recon --domain example.com --httpx --crawl --xss --ai-suggest \
  --ai-provider openai --ai-key "your-api-key"

# Custom XSS payload
ezrec recon --domain example.com --httpx --crawl --xss \
  --payload "<img src=x onerror=alert('XSS')>"
```

### Nuclei Vulnerability Scanning

```bash
# Basic Nuclei scanning
ezrec recon --domain example.com --httpx --nuclei

# Nuclei with custom templates and severity
ezrec recon --domain example.com --httpx --nuclei \
  --nuclei-templates "./custom-templates/" \
  --nuclei-severity "critical,high"

# Nuclei with specific tags
ezrec recon --domain example.com --httpx --nuclei \
  --nuclei-tags "exposure,config,backup"
```

### FFUF Directory/File Fuzzing

```bash
# Basic fuzzing
ezrec recon --domain example.com --httpx --ffuf

# Advanced fuzzing with custom parameters
ezrec recon --domain example.com --httpx --ffuf \
  --arcs 10000 \
  --ffuf-wordlist "/path/to/custom-wordlist.txt"
```

### Telegram Notifications

```bash
# Set up Telegram notifications
export EZREC_TELEGRAM_TOKEN="123456:ABCDEF-your-bot-token"
export EZREC_TELEGRAM_CHAT="987654321"

# Or use command line flags
ezrec recon --domain example.com --subdomains --httpx \
  --telegram-token "123456:ABCDEF" \
  --telegram-chat "987654321"
```

## Rate Limiting and Headers

### Custom Rate Limiting

```bash
# Conservative rate limiting for sensitive targets
ezrec recon --domain example.com --subdomains --httpx \
  --rate 2 --concurrency 10 --timeout 60s

# Aggressive scanning (use with caution)
ezrec recon --domain example.com --subdomains --httpx \
  --rate 20 --concurrency 100
```

### Custom Headers

```bash
# Add custom headers for specific bug bounty platforms
ezrec recon --domain example.com --subdomains --httpx \
  --headers "X-Bug-Bounty-Platform=hackerone,Authorization=Bearer token123"

# Custom User-Agent
ezrec recon --domain example.com --subdomains --httpx \
  --user-agent "MyCustomBot/1.0 (Bug Bounty Research)"
```

## Output and Reporting

### Custom Output Directory

```bash
# Specify custom output directory
ezrec recon --domain example.com --subdomains --httpx \
  --outdir "/path/to/results"

# Results will be saved to:
# /path/to/results/example/
```

### Resume Previous Scans

```bash
# Resume a previous incomplete scan
ezrec recon --program example --resume --nuclei --ffuf
```

## Complete Workflow Examples

### Comprehensive Bug Bounty Recon

```bash
# Step 1: Create program configuration
cat > profiles/target-program.yml << EOF
program: "target-program"
rate: 5
concurrency: 50
timeout: 30s

headers:
  User-Agent: "ezrec/1.0 (Bug Bounty Research)"
  X-Researcher: "your-username"

scope:
  include:
    - ".*\\.target\\.com$"
    - ".*\\.target\\.org$"
  exclude:
    - ".*\\.staging\\..*"
    - ".*\\.test\\..*"
EOF

# Step 2: Run full reconnaissance pipeline
ezrec recon --program target-program \
  --domain target.com \
  --subdomains \
  --httpx \
  --crawl \
  --urls \
  --endpoints \
  --xss --ai-suggest \
  --nuclei --nuclei-severity "critical,high,medium" \
  --ffuf --arcs 5000 \
  --telegram-token "your-token" --telegram-chat "your-chat-id" \
  --verbose
```

### Quick Subdomain Discovery

```bash
# Fast subdomain enumeration for initial reconnaissance
ezrec recon --domain example.com --subdomains --httpx \
  --rate 10 --concurrency 100 \
  --outdir "./quick-recon"
```

### Deep Vulnerability Assessment

```bash
# Focus on vulnerability discovery for known live hosts
echo -e "https://app.example.com\nhttps://api.example.com\nhttps://admin.example.com" > live-hosts.txt

ezrec recon --seed-file live-hosts.txt \
  --crawl \
  --endpoints \
  --xss --ai-suggest --payload "<script>alert(document.domain)</script>" \
  --nuclei --nuclei-templates "./templates/" \
  --ffuf --arcs 15000 \
  --rate 3 --concurrency 20
```

### Continuous Monitoring Setup

```bash
#!/bin/bash
# continuous-recon.sh - Run ezrec periodically

PROGRAM="target-program"
DOMAIN="target.com"
TELEGRAM_TOKEN="your-token"
CHAT_ID="your-chat-id"

# Run daily reconnaissance
ezrec recon --program $PROGRAM \
  --domain $DOMAIN \
  --subdomains \
  --httpx \
  --crawl \
  --endpoints \
  --nuclei \
  --telegram-token $TELEGRAM_TOKEN \
  --telegram-chat $CHAT_ID \
  --outdir "./daily-recon/$(date +%Y%m%d)"

# Archive old results (keep last 30 days)
find ./daily-recon -type d -mtime +30 -exec rm -rf {} \;
```

## Tips and Best Practices

### 1. Start Small
```bash
# Always start with basic reconnaissance
ezrec recon --domain example.com --subdomains --httpx
```

### 2. Use Program Profiles
```bash
# Create program-specific configurations for consistent results
ezrec recon --program hackerone --seed-file targets.txt --subdomains --httpx
```

### 3. Respect Rate Limits
```bash
# Use conservative rate limits for production systems
ezrec recon --domain example.com --rate 2 --concurrency 10 --subdomains --httpx
```

### 4. Enable Notifications
```bash
# Stay informed about long-running scans
ezrec recon --domain example.com --subdomains --httpx --crawl \
  --telegram-token "token" --telegram-chat "chat-id"
```

### 5. Combine with Other Tools
```bash
# Use ezrec output as input for other tools
ezrec recon --domain example.com --subdomains --httpx
cat results/example/httpx.csv | cut -d',' -f5 | tail -n +2 > live-hosts.txt
```

## Troubleshooting

### Common Issues

1. **Tool Not Found**: Install required tools using `./install-tools.sh` or `install-tools.bat`

2. **Rate Limiting**: Reduce `--rate` and `--concurrency` values

3. **Timeout Errors**: Increase `--timeout` value

4. **Scope Issues**: Check your include/exclude patterns in program profiles

5. **Output Permissions**: Ensure write permissions for `--outdir`

### Debug Mode

```bash
# Enable verbose output for debugging
ezrec recon --domain example.com --subdomains --httpx --verbose

# Check configuration
ezrec recon --program example --domain example.com --verbose
```

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/recon.yml
name: Continuous Recon
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  recon:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
      - run: ./install-tools.sh
      - run: |
          ezrec recon --program ${{ secrets.PROGRAM_NAME }} \
            --domain ${{ secrets.TARGET_DOMAIN }} \
            --subdomains --httpx --crawl \
            --telegram-token ${{ secrets.TELEGRAM_TOKEN }} \
            --telegram-chat ${{ secrets.TELEGRAM_CHAT }}
```

### Docker Usage

```dockerfile
FROM golang:1.21-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY . .
RUN go build -o ezrec main.go
RUN ./install-tools.sh
ENTRYPOINT ["./ezrec"]
```

```bash
# Build and run with Docker
docker build -t ezrec .
docker run -v $(pwd)/out:/app/out ezrec recon --domain example.com --subdomains --httpx
```