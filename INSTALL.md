# ezrec Installation Guide

This guide provides detailed installation instructions for ezrec on different operating systems and environments.

## 🚀 Quick Installation

### One-Line Install (Linux/macOS)

```bash
# Install ezrec and all dependencies
curl -sSL https://raw.githubusercontent.com/ezrec/ezrec/main/install.sh | bash
```

### One-Line Install (Windows PowerShell)

```powershell
# Install ezrec and all dependencies
iwr -useb https://raw.githubusercontent.com/ezrec/ezrec/main/install.ps1 | iex
```

## 📦 Package Manager Installation

### Homebrew (macOS/Linux)

```bash
# Add tap (when available)
brew tap ezrec/tap
brew install ezrec

# Install external tools
ezrec install-tools
```

### Chocolatey (Windows)

```powershell
# Install ezrec (when available)
choco install ezrec

# Install external tools
ezrec install-tools
```

### APT (Ubuntu/Debian)

```bash
# Add repository (when available)
curl -fsSL https://packages.ezrec.dev/gpg | sudo apt-key add -
echo "deb https://packages.ezrec.dev/apt stable main" | sudo tee /etc/apt/sources.list.d/ezrec.list
sudo apt update
sudo apt install ezrec

# Install external tools
ezrec install-tools
```

## 🔧 Manual Installation

### Prerequisites

All platforms require:
- **Go 1.21+** - [Download](https://golang.org/dl/)
- **Git** - For cloning repositories

### Platform-Specific Prerequisites

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install golang-go git curl wget
```

#### CentOS/RHEL/Fedora
```bash
# Fedora/CentOS Stream
sudo dnf install golang git curl wget

# RHEL/CentOS 7
sudo yum install golang git curl wget
```

#### macOS
```bash
# Using Homebrew
brew install go git

# Using MacPorts
sudo port install go git
```

#### Windows
1. Download Go from https://golang.org/dl/ (choose .msi installer)
2. Download Git from https://git-scm.com/download/win
3. Install both using the downloaded installers

### Build from Source

#### Step 1: Clone Repository

```bash
git clone https://github.com/ezrec/ezrec.git
cd ezrec
```

#### Step 2: Build Binary

**Linux/macOS:**
```bash
# Build for current platform
go build -o ezrec main.go

# Build for specific platforms
GOOS=linux GOARCH=amd64 go build -o ezrec-linux-amd64 main.go
GOOS=darwin GOARCH=amd64 go build -o ezrec-darwin-amd64 main.go
GOOS=darwin GOARCH=arm64 go build -o ezrec-darwin-arm64 main.go

# Install system-wide
sudo install -m 755 ezrec /usr/local/bin/
```

**Windows:**
```powershell
# Build for Windows
go build -o ezrec.exe main.go

# Build for other platforms
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -o ezrec-windows-amd64.exe main.go
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o ezrec-linux-amd64 main.go
```

#### Step 3: Install External Tools

**Linux/macOS:**
```bash
chmod +x install-tools.sh
./install-tools.sh
```

**Windows:**
```powershell
.\install-tools.bat
```

### Direct Go Install

```bash
# Install latest version
go install github.com/ezrec/ezrec@latest

# Install specific version
go install github.com/ezrec/ezrec@v1.0.0

# The binary will be installed to:
# - Linux/macOS: $HOME/go/bin/ezrec
# - Windows: %USERPROFILE%\go\bin\ezrec.exe
```

## 🐳 Docker Installation

### Using Pre-built Image

```bash
# Pull and run
docker pull ghcr.io/ezrec/ezrec:latest
docker run --rm -v $(pwd)/out:/app/out ghcr.io/ezrec/ezrec:latest --help

# Create alias
echo 'alias ezrec="docker run --rm -v $(pwd)/out:/app/out ghcr.io/ezrec/ezrec:latest"' >> ~/.bashrc
```

### Building from Source

```bash
# Clone and build
git clone https://github.com/ezrec/ezrec.git
cd ezrec
docker build -t ezrec .

# Run
docker run --rm -v $(pwd)/out:/app/out ezrec --help
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: '3.8'
services:
  ezrec:
    image: ghcr.io/ezrec/ezrec:latest
    volumes:
      - ./out:/app/out
      - ./profiles:/app/profiles
    command: recon --domain example.com --subdomains --httpx
```

Run with:
```bash
docker-compose run --rm ezrec --help
```

## 🔍 Verification

### Test Installation

```bash
# Test ezrec
ezrec --version
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

### Run Test Scan

```bash
# Basic test
ezrec recon --domain example.com --subdomains --httpx --verbose

# Check output
ls -la out/
```

## 🛠️ External Tools Details

ezrec integrates with these external tools:

| Tool | Purpose | Installation |
|------|---------|-------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [amass](https://github.com/OWASP/Amass) | Subdomain enumeration | `go install github.com/OWASP/Amass/v4/...@master` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [gau](https://github.com/lc/gau) | Historical URLs | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Wayback URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |
| [ffuf](https://github.com/ffuf/ffuf) | Web fuzzing | `go install github.com/ffuf/ffuf@latest` |

## 🚨 Troubleshooting

### Common Issues

#### "ezrec: command not found"

**Cause:** Binary not in PATH

**Solutions:**
```bash
# Linux/macOS - Add to PATH
export PATH=$PATH:/usr/local/bin
export PATH=$PATH:$HOME/go/bin

# Make permanent
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Windows - Add to PATH
$env:PATH += ";C:\path\to\ezrec"
# Or use System Properties > Environment Variables
```

#### "go: command not found"

**Cause:** Go not installed or not in PATH

**Solutions:**
- Install Go from https://golang.org/dl/
- Restart terminal after installation
- Verify with `go version`

#### External tools not found

**Cause:** Tools not installed or not in PATH

**Solutions:**
```bash
# Run installation script
./install-tools.sh          # Linux/macOS
.\install-tools.bat         # Windows

# Check PATH includes Go bin directory
echo $PATH | grep go        # Linux/macOS
echo $env:PATH | findstr go # Windows

# Verify tool installation
which subfinder             # Linux/macOS
where subfinder             # Windows
```

#### Permission denied (Linux/macOS)

**Cause:** Binary not executable or insufficient permissions

**Solutions:**
```bash
# Make executable
chmod +x ezrec

# Install system-wide
sudo install -m 755 ezrec /usr/local/bin/

# Run from current directory
./ezrec --help
```

#### Docker issues

**Solutions:**
```bash
# Check Docker installation
docker --version

# Pull latest image
docker pull ghcr.io/ezrec/ezrec:latest

# Check volume mounts
docker run --rm -v $(pwd)/out:/app/out ghcr.io/ezrec/ezrec:latest ls -la /app/out
```

### Getting Help

- 📖 [Documentation](https://github.com/ezrec/ezrec/wiki)
- 🐛 [Issue Tracker](https://github.com/ezrec/ezrec/issues)
- 💬 [Discussions](https://github.com/ezrec/ezrec/discussions)
- 📧 [Email Support](mailto:support@ezrec.dev)

### Reporting Issues

When reporting issues, please include:

1. **System Information:**
   ```bash
   # Linux/macOS
   uname -a
   go version
   
   # Windows
   systeminfo | findstr /C:"OS Name" /C:"OS Version"
   go version
   ```

2. **Installation Method:** Source, binary, Docker, etc.

3. **Error Messages:** Full error output with `--verbose` flag

4. **Steps to Reproduce:** Exact commands used

## 🔄 Updates

### Update ezrec

```bash
# From source
cd ezrec
git pull
go build -o ezrec main.go

# From Go modules
go install github.com/ezrec/ezrec@latest

# Docker
docker pull ghcr.io/ezrec/ezrec:latest
```

### Update External Tools

```bash
# Re-run installation script
./install-tools.sh          # Linux/macOS
.\install-tools.bat         # Windows

# Update specific tool
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

## 📝 Configuration

After installation, you may want to:

1. **Create program profiles:** `mkdir profiles && cp profiles/example.yml profiles/myprogram.yml`
2. **Configure API keys:** Set environment variables for AI and Telegram
3. **Customize templates:** Add custom Nuclei templates to `templates/`
4. **Add wordlists:** Place custom wordlists in `wordlists/`

See [Configuration Guide](CONFIGURATION.md) for detailed setup instructions.