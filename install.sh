#!/bin/bash

# Secure Vibe MCP Installation Script
# Supports: Linux, macOS, Windows (WSL)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║           🔒 Secure Vibe MCP Installer                     ║"
    echo "║                                                            ║"
    echo "║   AI-powered security scanning & auto-patching             ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Check Python version
check_python() {
    log_info "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        log_error "Python is not installed. Please install Python 3.9 or higher."
        exit 1
    fi
    
    PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    log_info "Found Python $PYTHON_VERSION"
    
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
        log_error "Python 3.9 or higher is required. Found: $PYTHON_VERSION"
        exit 1
    fi
    
    log_success "Python version check passed"
}

# Check pip
check_pip() {
    log_info "Checking pip installation..."
    
    if ! $PYTHON_CMD -m pip --version &> /dev/null; then
        log_error "pip is not installed. Please install pip."
        exit 1
    fi
    
    log_success "pip is available"
}

# Create virtual environment
setup_venv() {
    log_info "Setting up virtual environment..."
    
    if [ -d ".venv" ]; then
        log_warning "Virtual environment already exists. Removing old environment..."
        rm -rf .venv
    fi
    
    $PYTHON_CMD -m venv .venv
    
    if [ -f ".venv/bin/activate" ]; then
        source .venv/bin/activate
    elif [ -f ".venv/Scripts/activate" ]; then
        source .venv/Scripts/activate
    else
        log_error "Failed to create virtual environment"
        exit 1
    fi
    
    log_success "Virtual environment created and activated"
}

# Install dependencies
install_dependencies() {
    log_info "Installing dependencies..."
    
    pip install --upgrade pip setuptools wheel
    
    if [ -f "pyproject.toml" ]; then
        pip install -e .
    elif [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
    else
        log_warning "No pyproject.toml or requirements.txt found"
    fi
    
    log_success "Dependencies installed"
}

# Create configuration directory
setup_config() {
    log_info "Setting up configuration..."
    
    mkdir -p config
    
    if [ -f "config/mcp-config.json" ]; then
        log_info "MCP configuration already exists"
    else
        log_warning "MCP config not found. Run from project root."
    fi
    
    # Create .env template if it doesn't exist
    if [ ! -f ".env.template" ]; then
        cat > .env.template << 'EOF'
# Secure Vibe MCP Configuration
SEVERITY_THRESHOLD=medium
AUTO_PATCH=false
RULES_PATH=./src/scanner/rules/rules.yaml
BACKUP_ENABLED=true
PARALLEL_SCANNING=true
MAX_WORKERS=4
LOG_LEVEL=INFO
OUTPUT_FORMAT=json
ENABLE_SEMANTIC_ANALYSIS=true
ENABLE_DATAFLOW_ANALYSIS=true
EOF
        log_success "Created .env.template"
    fi
    
    log_success "Configuration setup complete"
}

# Create shell aliases
create_aliases() {
    log_info "Creating shell aliases..."
    
    SHELL_NAME=$(basename "$SHELL")
    
    case "$SHELL_NAME" in
        bash)
            RC_FILE="$HOME/.bashrc"
            ;;
        zsh)
            RC_FILE="$HOME/.zshrc"
            ;;
        fish)
            RC_FILE="$HOME/.config/fish/config.fish"
            ;;
        *)
            log_warning "Unknown shell: $SHELL_NAME. Skipping alias creation."
            return
            ;;
    esac
    
    # Check if aliases already exist
    if grep -q "secure-vibe" "$RC_FILE" 2>/dev/null; then
        log_warning "Aliases already exist in $RC_FILE"
        return
    fi
    
    cat >> "$RC_FILE" << EOF

# Secure Vibe MCP Aliases
alias secure-vibe='cd $SCRIPT_DIR && source .venv/bin/activate && python -m src.cli'
alias secure-vibe-scan='secure-vibe scan'
alias secure-vibe-report='secure-vibe report'
alias secure-vibe-patch='secure-vibe patch'
EOF
    
    log_success "Created aliases in $RC_FILE"
    log_info "Run 'source $RC_FILE' to load aliases"
}

# Run test scan
run_test_scan() {
    log_info "Running test scan..."
    
    if [ -d "tests/sample_vulnerable" ]; then
        log_info "Scanning sample vulnerable files..."
        
        if $PYTHON_CMD -m src.cli scan --file tests/sample_vulnerable/app.js 2>/dev/null; then
            log_success "Test scan completed successfully"
        else
            log_warning "Test scan had issues, but installation may still be working"
        fi
    else
        log_warning "No sample files found. Skipping test scan."
    fi
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
    echo -e "║                     Installation Complete!                 ║"
    echo -e "╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Activate virtual environment: source .venv/bin/activate"
    echo "  2. Run a scan: python -m src.cli scan --file <file>"
    echo "  3. Generate report: python -m src.cli report --output report.html"
    echo
    echo -e "${BLUE}MCP Integration:${NC}"
    echo "  • Claude Desktop: Add config/mcp-config.json to ~/.config/claude/config.json"
    echo "  • Cursor: Add config/mcp-config.json to .cursor/mcp.json"
    echo "  • Windsurf: Add config to your Windsurf MCP settings"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "  • README.md - Full documentation"
    echo "  • examples/ - Usage examples and integration guides"
    echo
    echo -e "${BLUE}Support:${NC}"
    echo "  • Issues: https://github.com/yourusername/secure-vibe-mcp/issues"
    echo "  • Docs: https://docs.secure-vibe.dev"
    echo
}

# Main installation flow
main() {
    print_banner
    
    log_info "Starting installation..."
    
    check_python
    check_pip
    setup_venv
    install_dependencies
    setup_config
    create_aliases
    run_test_scan
    
    print_completion
}

# Handle script interruption
trap 'log_error "Installation interrupted"; exit 1' INT TERM

# Run main function
main
