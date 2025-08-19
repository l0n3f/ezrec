#!/bin/bash

# ezrec Quick Installation Script
# This script downloads and installs ezrec with all dependencies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_banner() {
    echo -e "${PURPLE}"
    echo "=================================================================="
    echo "                    ezrec Quick Installer"
    echo "          Bug Bounty Reconnaissance Orchestrator"
    echo "=================================================================="
    echo -e "${NC}"
}

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

print_info() {
    echo -e "${CYAN}ℹ️${NC} $1"
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    
    case $ARCH in
        x86_64|amd64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        armv7l) ARCH="arm" ;;
        *) print_error "Unsupported architecture: $ARCH"; exit 1 ;;
    esac
    
    case $OS in
        linux) PLATFORM="linux-$ARCH" ;;
        darwin) PLATFORM="darwin-$ARCH" ;;
        *) print_error "Unsupported OS: $OS"; exit 1 ;;
    esac
    
    print_info "Detected platform: $PLATFORM"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install Go if not present
install_go() {
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        print_success "Go is already installed: $GO_VERSION"
        return 0
    fi
    
    print_status "Go not found. Installing Go..."
    
    GO_VERSION="1.21.5"
    GO_TARBALL="go${GO_VERSION}.${PLATFORM}.tar.gz"
    GO_URL="https://golang.org/dl/$GO_TARBALL"
    
    # Download Go
    print_status "Downloading Go $GO_VERSION..."
    if command_exists curl; then
        curl -sSL "$GO_URL" -o "/tmp/$GO_TARBALL"
    elif command_exists wget; then
        wget -q "$GO_URL" -O "/tmp/$GO_TARBALL"
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    # Install Go
    print_status "Installing Go to /usr/local/go..."
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/$GO_TARBALL"
    rm "/tmp/$GO_TARBALL"
    
    # Add Go to PATH
    export PATH="/usr/local/go/bin:$PATH"
    
    # Add to shell profile
    for profile in ~/.bashrc ~/.zshrc ~/.profile; do
        if [[ -f "$profile" ]]; then
            if ! grep -q "/usr/local/go/bin" "$profile"; then
                echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$profile"
                print_info "Added Go to PATH in $profile"
            fi
        fi
    done
    
    print_success "Go installed successfully"
}

# Install ezrec from source
install_ezrec_source() {
    print_status "Installing ezrec from source..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone repository
    print_status "Cloning ezrec repository..."
    if command_exists git; then
        git clone https://github.com/ezrec/ezrec.git
        cd ezrec
    else
        print_error "Git is not installed. Please install git first."
        exit 1
    fi
    
    # Build binary
    print_status "Building ezrec binary..."
    go build -o ezrec main.go
    
    # Install binary
    print_status "Installing ezrec to /usr/local/bin..."
    sudo install -m 755 ezrec /usr/local/bin/
    
    # Copy configuration files
    print_status "Installing configuration files..."
    sudo mkdir -p /usr/local/share/ezrec
    sudo cp -r profiles templates wordlists /usr/local/share/ezrec/
    sudo cp install-tools.sh /usr/local/share/ezrec/
    sudo chmod +x /usr/local/share/ezrec/install-tools.sh
    
    # Clean up
    cd /
    rm -rf "$TEMP_DIR"
    
    print_success "ezrec installed successfully"
}

# Install ezrec from pre-built binary
install_ezrec_binary() {
    print_status "Installing ezrec from pre-built binary..."
    
    # Download binary
    BINARY_URL="https://github.com/ezrec/ezrec/releases/latest/download/ezrec-$PLATFORM"
    print_status "Downloading ezrec binary..."
    
    if command_exists curl; then
        curl -sSL "$BINARY_URL" -o /tmp/ezrec
    elif command_exists wget; then
        wget -q "$BINARY_URL" -O /tmp/ezrec
    else
        print_error "Neither curl nor wget found. Please install one of them."
        exit 1
    fi
    
    # Install binary
    chmod +x /tmp/ezrec
    sudo mv /tmp/ezrec /usr/local/bin/
    
    # Download configuration files
    print_status "Downloading configuration files..."
    sudo mkdir -p /usr/local/share/ezrec
    
    CONFIG_FILES=("profiles/example.yml" "install-tools.sh" "templates/exposures.yaml" "templates/admin-panels.yaml" "wordlists/common.txt")
    
    for file in "${CONFIG_FILES[@]}"; do
        file_url="https://raw.githubusercontent.com/ezrec/ezrec/main/$file"
        file_dir=$(dirname "$file")
        sudo mkdir -p "/usr/local/share/ezrec/$file_dir"
        
        if command_exists curl; then
            sudo curl -sSL "$file_url" -o "/usr/local/share/ezrec/$file"
        else
            sudo wget -q "$file_url" -O "/usr/local/share/ezrec/$file"
        fi
    done
    
    sudo chmod +x /usr/local/share/ezrec/install-tools.sh
    
    print_success "ezrec installed successfully"
}

# Install external tools
install_external_tools() {
    print_status "Installing external reconnaissance tools..."
    
    # Ensure Go bin is in PATH
    export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"
    
    # Install tools
    if [[ -f "/usr/local/share/ezrec/install-tools.sh" ]]; then
        /usr/local/share/ezrec/install-tools.sh
    else
        # Fallback: install tools directly
        print_status "Installing tools directly..."
        
        tools=(
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            "github.com/projectdiscovery/httpx/cmd/httpx@latest"
            "github.com/projectdiscovery/katana/cmd/katana@latest"
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
            "github.com/OWASP/Amass/v4/...@master"
            "github.com/lc/gau/v2/cmd/gau@latest"
            "github.com/tomnomnom/waybackurls@latest"
            "github.com/ffuf/ffuf@latest"
        )
        
        for tool in "${tools[@]}"; do
            tool_name=$(basename "$tool" | cut -d'@' -f1)
            print_status "Installing $tool_name..."
            go install -v "$tool" || print_warning "Failed to install $tool_name"
        done
    fi
}

# Create symlinks for configuration files
setup_config() {
    print_status "Setting up configuration..."
    
    # Create user config directory
    mkdir -p "$HOME/.config/ezrec"
    
    # Create symlinks if they don't exist
    for dir in profiles templates wordlists; do
        if [[ ! -e "$HOME/.config/ezrec/$dir" ]]; then
            ln -s "/usr/local/share/ezrec/$dir" "$HOME/.config/ezrec/$dir"
        fi
    done
    
    print_success "Configuration setup completed"
}

# Verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Test ezrec
    if command_exists ezrec; then
        print_success "ezrec is available"
        EZREC_VERSION=$(ezrec --version 2>/dev/null || echo "unknown")
        print_info "Version: $EZREC_VERSION"
    else
        print_error "ezrec is not available in PATH"
        return 1
    fi
    
    # Test external tools
    tools=("subfinder" "httpx" "katana" "nuclei" "amass" "gau" "waybackurls" "ffuf")
    available_tools=0
    
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            print_success "$tool is available"
            ((available_tools++))
        else
            print_warning "$tool is not available"
        fi
    done
    
    print_info "Available tools: $available_tools/${#tools[@]}"
}

# Show completion message
show_completion() {
    echo ""
    print_success "Installation completed successfully!"
    echo ""
    echo -e "${CYAN}🚀 Quick Start:${NC}"
    echo "  ezrec --help"
    echo "  ezrec recon --domain example.com --subdomains --httpx"
    echo ""
    echo -e "${CYAN}📁 Configuration files:${NC}"
    echo "  ~/.config/ezrec/profiles/  - Program configurations"
    echo "  ~/.config/ezrec/templates/ - Nuclei templates"
    echo "  ~/.config/ezrec/wordlists/ - Fuzzing wordlists"
    echo ""
    echo -e "${CYAN}🔧 Troubleshooting:${NC}"
    echo "  - Restart your terminal to refresh PATH"
    echo "  - Run 'source ~/.bashrc' or 'source ~/.zshrc'"
    echo "  - Check tools with: ezrec recon --help"
    echo ""
    echo -e "${CYAN}📖 Documentation:${NC}"
    echo "  https://github.com/ezrec/ezrec"
    echo ""
}

# Main installation function
main() {
    print_banner
    
    # Check for root privileges for system installation
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root. This will install system-wide."
    else
        print_info "Running as user. Will use sudo for system installation."
    fi
    
    # Detect platform
    detect_platform
    
    # Install dependencies
    print_status "Checking system dependencies..."
    
    # Install Go if needed
    install_go
    
    # Install Git if needed
    if ! command_exists git; then
        print_status "Installing git..."
        case $OS in
            linux)
                if command_exists apt-get; then
                    sudo apt-get update && sudo apt-get install -y git
                elif command_exists yum; then
                    sudo yum install -y git
                elif command_exists dnf; then
                    sudo dnf install -y git
                else
                    print_error "Cannot install git automatically. Please install git manually."
                    exit 1
                fi
                ;;
            darwin)
                if command_exists brew; then
                    brew install git
                else
                    print_error "Please install git manually or install Homebrew first."
                    exit 1
                fi
                ;;
        esac
    fi
    
    # Choose installation method
    if [[ "${INSTALL_METHOD:-}" == "source" ]] || ! command_exists curl && ! command_exists wget; then
        install_ezrec_source
    else
        install_ezrec_binary
    fi
    
    # Install external tools
    install_external_tools
    
    # Setup configuration
    setup_config
    
    # Verify installation
    verify_installation
    
    # Show completion message
    show_completion
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --source)
            INSTALL_METHOD="source"
            shift
            ;;
        --help|-h)
            echo "ezrec Quick Installer"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --source    Install from source code instead of binary"
            echo "  --help      Show this help message"
            echo ""
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Run main installation
main