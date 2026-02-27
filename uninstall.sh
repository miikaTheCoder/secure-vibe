#!/bin/bash

# Secure Vibe MCP Uninstallation Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

echo -e "${RED}"
echo "╔════════════════════════════════════════════════════════════╗"
echo "║            🔒 Secure Vibe MCP Uninstaller                 ║"
echo "╚════════════════════════════════════════════════════════════╝${NC}"
echo

# Remove virtual environment
if [ -d ".venv" ]; then
    log_info "Removing virtual environment..."
    rm -rf .venv
    log_success "Virtual environment removed"
else
    log_warning "No virtual environment found"
fi

# Remove MCP configurations
log_info "Removing MCP configurations..."

# Kilo CLI
if [ -f "$HOME/.config/kilo/kilo.json" ]; then
    rm -f "$HOME/.config/kilo/kilo.json"
    log_success "Removed Kilo CLI config"
fi

# Claude Code
if [ -f "$HOME/.claude.json" ]; then
    if grep -q "secure-vibe" "$HOME/.claude.json" 2>/dev/null; then
        rm -f "$HOME/.claude.json"
        log_success "Removed Claude Code config"
    fi
fi

# Claude Desktop
if [ -f "$HOME/.config/Claude/config.json" ]; then
    if grep -q "secure-vibe" "$HOME/.config/Claude/config.json" 2>/dev/null; then
        rm -f "$HOME/.config/Claude/config.json"
        log_success "Removed Claude Desktop config"
    fi
fi

# Cursor
if [ -f "$HOME/.cursor/mcp.json" ]; then
    if grep -q "secure-vibe" "$HOME/.cursor/mcp.json" 2>/dev/null; then
        rm -f "$HOME/.cursor/mcp.json"
        log_success "Removed Cursor config"
    fi
fi

# Windsurf
if [ -f "$HOME/.codeium/windsurf/mcp_config.json" ]; then
    if grep -q "secure-vibe" "$HOME/.codeium/windsurf/mcp_config.json" 2>/dev/null; then
        rm -f "$HOME/.codeium/windsurf/mcp_config.json"
        log_success "Removed Windsurf config"
    fi
fi

# OpenCode (in project directory)
if [ -f "opencode.json" ]; then
    if grep -q "secure-vibe" "opencode.json" 2>/dev/null; then
        rm -f "opencode.json"
        log_success "Removed OpenCode config"
    fi
fi

echo
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗"
echo "║                  Uninstallation Complete!                ║"
echo "╚════════════════════════════════════════════════════════════╝${NC}"
echo
echo "What was removed:"
echo "  • Virtual environment (.venv)"
echo "  • MCP config files for all supported IDEs"
echo
echo "To fully remove Secure Vibe, also run:"
echo "  rm -rf /path/to/secure-vibe"
echo
