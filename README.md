# ezrec - Bug Bounty Recon Orchestrator

ezrec is a comprehensive bug bounty reconnaissance tool that automates the entire discovery pipeline from subdomain enumeration to vulnerability testing. It's designed to be modular, secure, and terminal-first, allowing you to adapt to different bug bounty program requirements while respecting rate limits, scopes, and custom headers.

## Features

### 🔍 Modular & Scalable Recon
- **Subdomain enumeration** with subfinder and amass
- **Host liveness and fingerprinting** with httpx
- **Endpoint crawling** with katana
- **Historical URL discovery** with gau and waybackurls
- **Critical endpoint classification** (login, admin, API, payments)

### ⚡ Advanced Testing
- **Interactive XSS testing** with prompt-based payload input
- **AI-powered payload suggestions** for enhanced testing
- **Nuclei integration** with enhanced external templates
- **Advanced fuzzing** with ffuf and configurable arc counts

### 📊 Structured Output & Reporting
- **Multiple output formats**: Markdown, CSV, and NDJSON for each stage
- **Intermediate files** for resuming incomplete scans (--resume)
- **Visual summaries** that are easy to share and analyze

### 📱 Integration & Alerts
- **Telegram notifications** for stage completion
- **Immediate critical alerts** for findings like exposed keys/tokens
- **Customizable alert keywords** and severity levels

### 🛡️ Security & Compliance
- **Rate limiting** and concurrency control to avoid server overload
- **Custom headers and authentication** configurable per program
- **Scope awareness** with regex inclusion/exclusion patterns
- **Backoff and jitter** to prevent detection and blocking

### 🎯 CLI-First & Customizable
- **Individual stage flags** for granular control
- **Program-specific configurations** via YAML profiles
- **Flexible inputs**: single domain, domain list, or previous results

## Installation

### Prerequisites

- **Go 1.21 or later** - [Download Go](https://golang.org/dl/)
- **Git** - For cloning the repository

### Method 1: Install from Source (Recommended)

#### 🐧 Linux / 🍎 macOS

```bash
# Install Go (if not already installed)
# Ubuntu/Debian:
sudo apt update && sudo apt install golang-go git

# CentOS/RHEL/Fedora:
sudo dnf install golang git
# or: sudo yum install golang git

# macOS (with Homebrew):
brew install go git

# Clone and build ezrec
git clone https://github.com/ezrec/ezrec.git
cd ezrec
go build -o ezrec main.go

# Make executable and add to PATH
chmod +x ezrec
sudo mv ezrec /usr/local/bin/

# Install required external tools
chmod +x install-tools.sh
./install-tools.sh

# Verify installation
ezrec --help
```

#### 🪟 Windows

```powershell
# Install Go from https://golang.org/dl/ (download .msi installer)
# Install Git from https://git-scm.com/download/win

# Clone and build ezrec
git clone https://github.com/ezrec/ezrec.git
cd ezrec
go build -o ezrec.exe main.go

# Install required external tools
.\install-tools.bat

# Add to PATH (optional - replace C:\path\to\ezrec with actual path)
$env:PATH += ";C:\path\to\ezrec"

# Verify installation
.\ezrec.exe --help
```

### Method 2: Direct Go Install

```bash
# Install directly from Go modules (any OS with Go installed)
go install github.com/ezrec/ezrec@latest

# The binary will be installed to $GOPATH/bin or $HOME/go/bin
# Make sure this directory is in your PATH
```

### Method 3: Download Pre-built Binaries

#### 🐧 Linux (x64)

```bash
# Download latest release
curl -L -o ezrec https://github.com/ezrec/ezrec/releases/latest/download/ezrec-linux-amd64
chmod +x ezrec
sudo mv ezrec /usr/local/bin/

# Install external tools
curl -L -o install-tools.sh https://raw.githubusercontent.com/ezrec/ezrec/main/install-tools.sh
chmod +x install-tools.sh && ./install-tools.sh
```

#### 🍎 macOS (x64/ARM64)

```bash
# Intel Macs
curl -L -o ezrec https://github.com/ezrec/ezrec/releases/latest/download/ezrec-darwin-amd64
# Apple Silicon Macs
curl -L -o ezrec https://github.com/ezrec/ezrec/releases/latest/download/ezrec-darwin-arm64

chmod +x ezrec
sudo mv ezrec /usr/local/bin/

# Install external tools
curl -L -o install-tools.sh https://raw.githubusercontent.com/ezrec/ezrec/main/install-tools.sh
chmod +x install-tools.sh && ./install-tools.sh
```

#### 🪟 Windows (x64)

```powershell
# Download using PowerShell
Invoke-WebRequest -Uri "https://github.com/ezrec/ezrec/releases/latest/download/ezrec-windows-amd64.exe" -OutFile "ezrec.exe"

# Download and run tool installer
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ezrec/ezrec/main/install-tools.bat" -OutFile "install-tools.bat"
.\install-tools.bat
```

### Installing External Tools

ezrec requires several external reconnaissance tools. Use the provided installation scripts:

#### 🐧 Linux / 🍎 macOS

```bash
# Run the installation script
./install-tools.sh

# Or install manually:
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/OWASP/Amass/v4/...@master
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/ffuf/ffuf@latest
```

#### 🪟 Windows

```powershell
# Run the installation script
.\install-tools.bat

# Or install manually using the same go install commands as above
```

### Docker Installation (All Platforms)

```bash
# Build Docker image
git clone https://github.com/ezrec/ezrec.git
cd ezrec
docker build -t ezrec .

# Run with Docker
docker run -v $(pwd)/out:/app/out ezrec recon --domain example.com --subdomains --httpx

# Create alias for easier use (Linux/macOS)
echo 'alias ezrec="docker run -v $(pwd)/out:/app/out ezrec"' >> ~/.bashrc
source ~/.bashrc
```

### Verification

After installation, verify that ezrec and external tools are working:

```bash
# Test ezrec
ezrec --help

# Test external tools
subfinder -version
httpx -version
katana -version
nuclei -version
amass -version
gau --help
waybackurls -h
ffuf -V
```

### Troubleshooting

#### Common Issues:

1. **"ezrec: command not found"**
   - Ensure the binary is in your PATH
   - On Linux/macOS: `export PATH=$PATH:/usr/local/bin`
   - On Windows: Add the directory to your PATH environment variable

2. **"go: command not found"**
   - Install Go from https://golang.org/dl/
   - Restart your terminal after installation

3. **External tools not found**
   - Run the appropriate install-tools script for your OS
   - Ensure `$GOPATH/bin` or `$HOME/go/bin` is in your PATH

4. **Permission denied (Linux/macOS)**
   - Make sure the binary is executable: `chmod +x ezrec`
   - Use `sudo` for system-wide installation

#### Getting Help:

- 📖 [Documentation](https://github.com/ezrec/ezrec/wiki)
- 🐛 [Issue Tracker](https://github.com/ezrec/ezrec/issues)
- 💬 [Discussions](https://github.com/ezrec/ezrec/discussions)

## Quick Start

### Basic Usage

```bash
# Full pipeline on a single domain
ezrec recon --domain example.com --subdomains --httpx --crawl --endpoints --xss --nuclei --ffuf

# Use a program-specific configuration
ezrec recon --program hackerone --seed-file domains.txt --subdomains --httpx --crawl

# Resume a previous scan
ezrec recon --program example --resume --nuclei --ffuf
```

### Advanced Examples

```bash
# XSS testing with AI-powered payload suggestions
ezrec recon --domain example.com --httpx --crawl --xss --ai-suggest \
  --payload "<script>alert(1)</script>" --ai-provider openai --ai-key YOUR_KEY

# Advanced fuzzing with custom parameters
ezrec recon --domain example.com --httpx --ffuf --arcs 10000 \
  --ffuf-wordlist /path/to/custom.txt

# Full pipeline with Telegram notifications
ezrec recon --program example --subdomains --httpx --crawl --xss --nuclei --ffuf \
  --telegram-token "123456:ABCDEF" --telegram-chat "987654321"

# Custom headers for specific bug bounty platforms
ezrec recon --domain example.com --subdomains --httpx \
  --headers "X-Bug-Bounty-Platform=hackerone,Authorization=Bearer token123"
```

## Configuration

### Program Profiles

Create program-specific configurations in `profiles/<program>.yml`:

```yaml
program: "example"
rate: 5
concurrency: 50
timeout: 30s
user_agent: "ezrec/1.0 (Bug Bounty Research Tool)"

headers:
  User-Agent: "ezrec/1.0 (Bug Bounty Research Tool)"
  X-Bug-Bounty-Platform: "hackerone"

scope:
  include:
    - ".*\\.example\\.com$"
    - ".*\\.example\\.org$"
  exclude:
    - ".*\\.staging\\..*"
    - ".*\\.dev\\..*"

# Tool-specific configurations...
```

### Environment Variables

```bash
export EZREC_TELEGRAM_TOKEN="your_bot_token"
export EZREC_TELEGRAM_CHAT="your_chat_id"
export EZREC_AI_API_KEY="your_openai_key"
```

## Command Reference

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--program` | Bug bounty program name | - |
| `--domain` | Single domain to scan | - |
| `--seed-file` | File with domain list | - |
| `--outdir` | Output directory | `./results` |
| `--rate` | Requests per second | `5` |
| `--concurrency` | Concurrent workers | `50` |
| `--timeout` | Request timeout | `30s` |
| `--headers` | Custom headers (key=value) | - |
| `--user-agent` | Custom User-Agent | - |
| `--verbose, -v` | Verbose output | `false` |
| `--quiet, -q` | Quiet output (errors only) | `false` |

### Stage Flags

| Flag | Description |
|------|-------------|
| `--subdomains` | Enable subdomain enumeration |
| `--httpx` | Enable host liveness checking |
| `--crawl` | Enable endpoint crawling |
| `--urls` | Enable historical URL discovery |
| `--endpoints` | Enable endpoint classification |
| `--xss` | Enable XSS testing |
| `--nuclei` | Enable Nuclei vulnerability scanning |
| `--ffuf` | Enable directory/file fuzzing |

### XSS Testing Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--payload` | XSS payload to test | `<script>alert(1)</script>` |
| `--ai-suggest` | Enable AI payload suggestions | `false` |

### Nuclei Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--nuclei-templates` | Templates directory | `./templates/` |
| `--nuclei-severity` | Severity levels | `critical,high,medium` |
| `--nuclei-tags` | Template tags to include | - |

### FFUF Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--arcs` | Number of paths to fuzz | `1000` |
| `--ffuf-wordlist` | Custom wordlist path | - |

### Telegram Flags

| Flag | Description |
|------|-------------|
| `--telegram-token` | Bot token |
| `--telegram-chat` | Chat ID |

### AI Integration Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--ai` | Enable AI features | `false` |
| `--ai-provider` | AI provider | `openai` |
| `--ai-key` | API key | - |
| `--ai-model` | Model name | `gpt-4` |

## Pipeline Stages

The reconnaissance pipeline executes stages in the following order:

```
[Seed domains] → Subdomain Enumeration → Host Probing → Crawling → 
Historical URLs → Endpoint Classification → XSS Testing → 
Nuclei Scanning → FFUF Fuzzing → Reports & Alerts
```

### Stage Outputs

Each stage generates structured output in multiple formats:

- **Markdown**: Human-readable reports with tables and summaries
- **CSV**: Machine-readable data for analysis and filtering  
- **NDJSON**: Structured data for integration with other tools

Example output structure:
```
results/
├── example/
│   ├── subdomains.md
│   ├── subdomains.csv
│   ├── subdomains.ndjson
│   ├── httpx.md
│   ├── httpx.csv
│   ├── httpx.ndjson
│   ├── crawl.md
│   ├── urls.md
│   ├── endpoints.md
│   ├── xss.md
│   ├── nuclei.md
│   ├── ffuf.md
│   └── README.md
```

## Integration with External Tools

ezrec integrates with the following tools (install separately):

### Required Tools
- [subfinder](https://github.com/projectdiscovery/subfinder) - Subdomain enumeration
- [amass](https://github.com/OWASP/Amass) - Subdomain enumeration
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP probing
- [katana](https://github.com/projectdiscovery/katana) - Web crawling
- [gau](https://github.com/lc/gau) - Historical URL discovery
- [waybackurls](https://github.com/tomnomnom/waybackurls) - Wayback Machine URLs
- [nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanning
- [ffuf](https://github.com/ffuf/ffuf) - Fuzzing

### Installation Script

```bash
#!/bin/bash
# Install required tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/ffuf/ffuf@latest
```

## AI Integration

ezrec supports AI-powered features for enhanced reconnaissance:

### Supported Providers
- **OpenAI** (GPT-3.5, GPT-4)
- **Anthropic** (Claude)
- **Ollama** (Local models)

### AI Features
- **Payload generation** for XSS testing
- **Vulnerability analysis** and risk assessment
- **Custom wordlist generation** for fuzzing
- **Report summarization** and insights

## Telegram Notifications

Configure Telegram notifications to stay updated on scan progress:

1. Create a Telegram bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID from [@userinfobot](https://t.me/userinfobot)
3. Configure ezrec with your bot token and chat ID

### Notification Types
- **Stage completion** with result counts
- **Critical findings** with immediate alerts
- **Error notifications** for failed stages
- **Final summary** with comprehensive results

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and setup
git clone https://github.com/ezrec/ezrec.git
cd ezrec

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Build
go build -o ezrec main.go
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is designed for authorized security testing and bug bounty research only. Users are responsible for complying with applicable laws and regulations. Always obtain proper authorization before testing any systems you do not own.

## Support

- 📖 [Documentation](https://github.com/ezrec/ezrec/wiki)
- 🐛 [Issue Tracker](https://github.com/ezrec/ezrec/issues)
- 💬 [Discussions](https://github.com/ezrec/ezrec/discussions)

---

**ezrec** - Streamline your bug bounty reconnaissance workflow 🎯