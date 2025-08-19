#!/bin/bash

# ezrec - Install Required Tools Script
# This script installs all the external tools required by ezrec

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}🔧${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_status "Installing required tools for ezrec..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go first:"
    echo "  Ubuntu/Debian: sudo apt install golang-go"
    echo "  CentOS/RHEL:   sudo dnf install golang"
    echo "  macOS:         brew install go"
    echo "  Or download from: https://golang.org/dl/"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_status "Found Go version: $GO_VERSION"

# Create Go bin directory if it doesn't exist
if [ ! -d "$HOME/go/bin" ]; then
    mkdir -p "$HOME/go/bin"
    print_status "Created Go bin directory: $HOME/go/bin"
fi

# Add Go bin to PATH if not already there
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    export PATH="$PATH:$HOME/go/bin"
    print_warning "Added $HOME/go/bin to PATH for this session"
    print_warning "Add 'export PATH=\$PATH:\$HOME/go/bin' to your ~/.bashrc or ~/.zshrc for permanent effect"
fi

print_status "Installing ProjectDiscovery tools..."

# Function to install a tool
install_tool() {
    local name=$1
    local url=$2
    local binary=$3
    
    print_status "Installing $name..."
    if go install -v "$url" 2>/dev/null; then
        if command -v "$binary" &> /dev/null; then
            print_success "$name installed successfully"
        else
            print_warning "$name installed but not found in PATH"
        fi
    else
        print_error "Failed to install $name"
        return 1
    fi
}

# Install ProjectDiscovery tools
install_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "subfinder"
install_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest" "httpx"
install_tool "katana" "github.com/projectdiscovery/katana/cmd/katana@latest" "katana"
install_tool "nuclei" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "nuclei"
install_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" "dnsx"

print_status "Installing other reconnaissance tools..."

# Install other tools
install_tool "amass" "github.com/OWASP/Amass/v4/...@master" "amass"
install_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest" "gau"
install_tool "waybackurls" "github.com/tomnomnom/waybackurls@latest" "waybackurls"
install_tool "ffuf" "github.com/ffuf/ffuf@latest" "ffuf"

print_success "All tools installation completed!"

# Verify installations
print_status "Verifying tool installations..."
tools=("subfinder" "httpx" "katana" "nuclei" "amass" "gau" "waybackurls" "ffuf")
failed_tools=()

for tool in "${tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        print_success "$tool is available"
    else
        print_warning "$tool is not available in PATH"
        failed_tools+=("$tool")
    fi
done

if [ ${#failed_tools[@]} -eq 0 ]; then
    print_success "All tools are properly installed and available!"
else
    print_warning "Some tools are not available in PATH: ${failed_tools[*]}"
    print_warning "Make sure $HOME/go/bin is in your PATH"
    print_warning "Run: export PATH=\$PATH:\$HOME/go/bin"
fi
echo ""
print_status "Installation Summary:"
echo "  📋 Installed tools:"
echo "    • subfinder - Subdomain enumeration"
echo "    • amass - Subdomain enumeration"  
echo "    • httpx - HTTP probing"
echo "    • katana - Web crawling"
echo "    • gau - Historical URL discovery"
echo "    • waybackurls - Wayback Machine URLs"
echo "    • nuclei - Vulnerability scanning"
echo "    • ffuf - Fuzzing"
echo "    • dnsx - DNS toolkit"
echo ""
print_success "Installation completed! You're ready to use ezrec!"
echo ""
print_status "Next steps:"
echo "  1. Make sure $HOME/go/bin is in your PATH"
echo "  2. Run 'ezrec --help' to get started"
echo "  3. Try 'ezrec recon --domain example.com --subdomains --httpx'"
echo ""
print_status "If you encounter any issues:"
echo "  - Check that Go is properly installed: go version"
echo "  - Verify tools are in PATH: which subfinder"
echo "  - Add to PATH: export PATH=\$PATH:\$HOME/go/bin"