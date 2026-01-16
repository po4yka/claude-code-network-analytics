#!/bin/bash
# Install MCP servers for Network Analytics Toolkit
#
# Usage: ./scripts/install-mcp.sh [--all|--custom|--external]
#   --all      Install custom and all external MCP servers
#   --custom   Install only the custom netanalytics-mcp server (default)
#   --external Install only external MCP servers (nmap, wiremcp, suricata)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MCP_DIR="$PROJECT_ROOT/mcp"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Parse arguments
INSTALL_CUSTOM=false
INSTALL_EXTERNAL=false

case "${1:-}" in
    --all)
        INSTALL_CUSTOM=true
        INSTALL_EXTERNAL=true
        ;;
    --external)
        INSTALL_EXTERNAL=true
        ;;
    --custom|"")
        INSTALL_CUSTOM=true
        ;;
    *)
        echo "Usage: $0 [--all|--custom|--external]"
        exit 1
        ;;
esac

# Check for uv
check_uv() {
    if ! command -v uv &> /dev/null; then
        info "uv not found, installing..."
        curl -LsSf https://astral.sh/uv/install.sh | sh
        export PATH="$HOME/.local/bin:$PATH"
    fi
    info "uv $(uv --version | cut -d' ' -f2) detected"
}

# Check Python version
check_python() {
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is required but not found"
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    if [ "$MAJOR" -lt 3 ] || ([ "$MAJOR" -eq 3 ] && [ "$MINOR" -lt 11 ]); then
        error "Python 3.11+ is required (found $PYTHON_VERSION)"
    fi

    info "Python $PYTHON_VERSION detected"
}

# Install custom netanalytics-mcp server
install_custom() {
    info "Installing custom netanalytics-mcp server..."

    # First install the main netanalytics package
    if [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
        error "pyproject.toml not found in project root"
    fi

    cd "$PROJECT_ROOT"

    info "Syncing project dependencies with uv..."
    uv sync

    # Add netanalytics-mcp as a workspace member or install it
    info "Installing netanalytics-mcp server..."
    uv pip install -e "$MCP_DIR/netanalytics-mcp"

    info "Custom MCP server installed successfully"
}

# Install external MCP servers
install_external() {
    info "Installing external MCP servers..."

    cd "$PROJECT_ROOT"

    # Check for npm/npx
    if ! command -v npx &> /dev/null; then
        warn "npx not found - skipping nmap-mcp-server"
    else
        info "nmap-mcp-server will be installed on first use via npx"
    fi

    # Install WireMCP
    if uv pip install wiremcp 2>/dev/null; then
        info "WireMCP installed"
    else
        warn "Failed to install WireMCP - it may not be available on PyPI"
    fi

    # Install SuricataMCP
    if uv pip install suricata-mcp 2>/dev/null; then
        info "SuricataMCP installed"
    else
        warn "Failed to install SuricataMCP - it may not be available on PyPI"
    fi

    info "External MCP servers installation complete"
}

# Verify installation
verify() {
    info "Verifying installation..."

    cd "$PROJECT_ROOT"

    if $INSTALL_CUSTOM; then
        if uv run python -c "import netanalytics_mcp" 2>/dev/null; then
            info "✓ netanalytics-mcp is importable"
        else
            warn "✗ netanalytics-mcp import failed"
        fi
    fi

    info "Installation verification complete"
}

# Print setup instructions
print_instructions() {
    echo ""
    echo "=========================================="
    echo "MCP Server Installation Complete"
    echo "=========================================="
    echo ""
    echo "To use with Claude Desktop, add to your settings.json:"
    echo "  Location: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)"
    echo "  Location: %APPDATA%/Claude/claude_desktop_config.json (Windows)"
    echo ""
    echo "Example configuration:"
    echo '  {
    "mcpServers": {
      "netanalytics": {
        "command": "uv",
        "args": ["run", "python", "-m", "netanalytics_mcp.server"],
        "cwd": "'"$PROJECT_ROOT"'"
      }
    }
  }'
    echo ""
    echo "To test the server:"
    echo "  uv run fastmcp dev $MCP_DIR/netanalytics-mcp/netanalytics_mcp/server.py"
    echo ""
    echo "For operations requiring root (ARP scan, packet capture):"
    echo "  sudo uv run python -m netanalytics_mcp.server"
    echo ""
}

# Main
main() {
    info "Network Analytics MCP Server Installer"
    echo ""

    check_uv
    check_python

    if $INSTALL_CUSTOM; then
        install_custom
    fi

    if $INSTALL_EXTERNAL; then
        install_external
    fi

    verify
    print_instructions
}

main
