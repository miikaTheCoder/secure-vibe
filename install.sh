#!/bin/bash

# Secure Vibe MCP Installation Script
# Supports: Linux, macOS, Windows (WSL)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Get actual username
USER_NAME=$(whoami)

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
    echo -e "${CYAN}"
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

# Ask for IDE/CLI and configure MCP
configure_mcp() {
    echo
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════╗"
    echo "║              MCP Configuration Setup                    ║"
    echo "╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo "Which IDE/CLI would you like to configure for Secure Vibe?"
    echo
    echo "  1) Kilo CLI"
    echo "  2) Claude Code"
    echo "  3) Claude Desktop"
    echo "  4) Cursor"
    echo "  5) Windsurf"
    echo "  6) OpenCode"
    echo "  7) Skip (I'll configure manually)"
    echo
    read -p "Enter your choice (1-7): " choice
    
    VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python"
    WORKING_DIR="$SCRIPT_DIR"
    
    case $choice in
        1)
            log_info "Configuring Kilo CLI..."
            mkdir -p "$HOME/.config/kilo"
            cat > "$HOME/.config/kilo/kilo.json" << EOF
{
  "mcp": {
    "secure_vibe": {
      "type": "local",
      "command": ["$VENV_PYTHON", "-m", "src.mcp_server"],
      "cwd": "$WORKING_DIR",
      "enabled": true
    }
  }
}
EOF
            log_success "Kilo CLI configured! Run 'kilo' to start."
            ;;
        2)
            log_info "Configuring Claude Code..."
            cat > "$HOME/.claude.json" << EOF
{
  "mcpServers": {
    "secure_vibe": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "src.mcp_server"],
      "env": {},
      "cwd": "$WORKING_DIR"
    }
  }
}
EOF
            log_success "Claude Code configured! Run 'claude' to start."
            ;;
        3)
            log_info "Configuring Claude Desktop..."
            mkdir -p "$HOME/.config/Claude"
            cat > "$HOME/.config/Claude/config.json" << EOF
{
  "mcpServers": {
    "secure_vibe": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "src.mcp_server"],
      "env": {},
      "cwd": "$WORKING_DIR"
    }
  }
}
EOF
            log_success "Claude Desktop configured! Restart Claude Desktop."
            ;;
        4)
            log_info "Configuring Cursor..."
            mkdir -p "$HOME/.cursor"
            cat > "$HOME/.cursor/mcp.json" << EOF
{
  "mcpServers": {
    "secure_vibe": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "src.mcp_server"],
      "env": {},
      "cwd": "$WORKING_DIR"
    }
  }
}
EOF
            log_success "Cursor configured! Restart Cursor."
            ;;
        5)
            log_info "Configuring Windsurf..."
            mkdir -p "$HOME/.codeium/windsurf"
            cat > "$HOME/.codeium/windsurf/mcp_config.json" << EOF
{
  "mcpServers": {
    "secure_vibe": {
      "command": "$VENV_PYTHON",
      "args": ["-m", "src.mcp_server"],
      "env": {},
      "cwd": "$WORKING_DIR"
    }
  }
}
EOF
            log_success "Windsurf configured! Restart Windsurf."
            ;;
        6)
            log_info "Configuring OpenCode..."
            cat > "$SCRIPT_DIR/opencode.json" << EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "mcp": {
    "secure_vibe": {
      "type": "local",
      "command": ["$VENV_PYTHON", "-m", "src.mcp_server"],
      "cwd": "$WORKING_DIR",
      "enabled": true
    }
  }
}
EOF
            log_success "OpenCode configured! Run 'opencode' in this directory."
            ;;
        7)
            log_info "Skipping MCP configuration."
            log_info "You can configure manually using: $VENV_PYTHON -m src.mcp_server"
            ;;
        *)
            log_warning "Invalid choice. Skipping MCP configuration."
            ;;
    esac
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
    echo "  • MCP was configured during installation above"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "  • README.md - Full documentation"
    echo "  • examples/ - Usage examples and integration guides"
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
    configure_mcp
    run_test_scan
    
    print_completion
}

# Handle script interruption
trap 'log_error "Installation interrupted"; exit 1' INT TERM

# Run main function
main
