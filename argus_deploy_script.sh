#!/bin/bash

#===============================================================================
# Argus Ninja Poller Deployment Script
# 
# This script automatically downloads, compiles, and deploys the argus-ninja-poller
# service with proper systemd configuration and security settings.
#
# Requirements: Ubuntu 22.04 LTS
# Usage: sudo ./deploy-argus-ninja-poller.sh
#===============================================================================

set -euo pipefail

# Configuration
SERVICE_NAME="argus-ninja-poller"
SERVICE_USER="argus-poller"
SERVICE_GROUP="argus-poller"
BINARY_PATH="/usr/local/bin/${SERVICE_NAME}"
CONFIG_DIR="/etc/${SERVICE_NAME}"
CONFIG_FILE="${CONFIG_DIR}/config.json"
STATE_FILE="${CONFIG_DIR}/state.json"
LOG_FILE="/var/log/${SERVICE_NAME}.log"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
GITHUB_REPO_URL="https://raw.githubusercontent.com/SlickHenry/Argus/refs/heads/main"
TEMP_DIR="/tmp/${SERVICE_NAME}-deploy"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Please use 'sudo $0'"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    log_step "Checking system compatibility..."
    
    if ! command -v systemctl &> /dev/null; then
        log_error "systemd is required but not found"
        exit 1
    fi
    
    # Check Ubuntu version
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            log_warn "This script is designed for Ubuntu. Your system: $ID"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    log_info "System compatibility check passed"
}

# Install Go if not present
install_go() {
    log_step "Checking Go installation..."
    
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go is already installed (version: $GO_VERSION)"
        return 0
    fi
    
    log_info "Installing Go from Ubuntu repositories..."
    
    # Update package lists
    apt-get update
    
    # Install Go and required dependencies
    apt-get install -y golang-go wget curl build-essential
    
    # Verify installation
    if command -v go &> /dev/null; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        log_info "Go installed successfully (version: $GO_VERSION)"
    else
        log_error "Go installation failed"
        exit 1
    fi
}

# Create service user and group
create_service_user() {
    log_step "Creating service user and group..."
    
    # Create group if it doesn't exist
    if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SERVICE_GROUP"
        log_info "Created group: $SERVICE_GROUP"
    else
        log_info "Group $SERVICE_GROUP already exists"
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        useradd --system \
                --gid "$SERVICE_GROUP" \
                --create-home \
                --home-dir "/var/lib/$SERVICE_USER" \
                --shell /usr/sbin/nologin \
                --comment "Argus Ninja Poller service user" \
                "$SERVICE_USER"
        log_info "Created user: $SERVICE_USER"
    else
        log_info "User $SERVICE_USER already exists"
    fi
}

# Download and compile the application
download_and_compile() {
    log_step "Downloading and compiling application..."
    
    # Create temporary directory
    mkdir -p "$TEMP_DIR"
    cd "$TEMP_DIR"
    
    # Download source code
    log_info "Downloading source code..."
    curl -fsSL "${GITHUB_REPO_URL}/main.go" -o main.go
    
    # Initialize Go module
    log_info "Initializing Go module..."
    export GOPATH="/tmp/go"
    export GOCACHE="/tmp/go-cache"
    
    go mod init argus-ninja-poller
    go mod tidy
    
    # Compile the application
    log_info "Compiling application..."
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o "${SERVICE_NAME}" main.go
    
    # Verify compilation
    if [[ ! -f "$SERVICE_NAME" ]]; then
        log_error "Compilation failed - binary not found"
        exit 1
    fi
    
    # Check if binary is executable
    if [[ ! -x "$SERVICE_NAME" ]]; then
        chmod +x "$SERVICE_NAME"
    fi
    
    log_info "Application compiled successfully"
}

# Setup directories and permissions
setup_directories() {
    log_step "Setting up directories and permissions..."
    
    # Create configuration directory
    mkdir -p "$CONFIG_DIR"
    chown root:root "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    
    # Create log file and set permissions
    touch "$LOG_FILE"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    # Create service user home directory
    mkdir -p "/var/lib/$SERVICE_USER"
    chown "$SERVICE_USER:$SERVICE_GROUP" "/var/lib/$SERVICE_USER"
    chmod 750 "/var/lib/$SERVICE_USER"
    
    log_info "Directories and permissions configured"
}

# Install binary
install_binary() {
    log_step "Installing binary..."
    
    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        log_info "Stopping existing service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    # Copy binary to system location
    cp "$TEMP_DIR/$SERVICE_NAME" "$BINARY_PATH"
    chown root:root "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    
    log_info "Binary installed to $BINARY_PATH"
}

# Download and install configuration
install_configuration() {
    log_step "Installing configuration..."
    
    # Download config.json if it doesn't exist
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_info "Downloading default configuration..."
        curl -fsSL "${GITHUB_REPO_URL}/config.json" -o "$CONFIG_FILE"
        
        # Set permissions
        chown root:"$SERVICE_GROUP" "$CONFIG_FILE"
        chmod 640 "$CONFIG_FILE"
        
        log_warn "Default configuration installed. You MUST edit $CONFIG_FILE before starting the service!"
        log_warn "Required changes:"
        log_warn "  - Update oauth2.client_id and oauth2.client_secret"
        log_warn "  - Configure syslog.server address"
        log_warn "  - Set appropriate organization_ids"
    else
        log_info "Configuration file already exists: $CONFIG_FILE"
    fi
    
    # Create state file with proper permissions
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{"last_polled_times":{},"first_run":true}' > "$STATE_FILE"
        chown "$SERVICE_USER:$SERVICE_GROUP" "$STATE_FILE"
        chmod 640 "$STATE_FILE"
        log_info "Created initial state file: $STATE_FILE"
    fi
}

# Create systemd service file
create_systemd_service() {
    log_step "Creating systemd service..."
    
    cat > "$SYSTEMD_SERVICE_FILE" << EOF
[Unit]
Description=Argus Ninja Poller - NinjaRMM API to Syslog Forwarder
Documentation=https://github.com/SlickHenry/Argus
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
ExecStart=$BINARY_PATH $CONFIG_FILE
WorkingDirectory=$CONFIG_DIR
Restart=always
RestartSec=10
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE
SyslogIdentifier=$SERVICE_NAME

# Security settings
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$CONFIG_DIR /var/log
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@debug @mount @cpu-emulation @obsolete @privileged @reboot @swap @raw-io
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectKernelLogs=true
ProtectHostname=true
ProtectClock=true

# Environment
Environment=GOMAXPROCS=1

[Install]
WantedBy=multi-user.target
EOF
    
    # Set proper permissions on service file
    chmod 644 "$SYSTEMD_SERVICE_FILE"
    
    log_info "Systemd service file created: $SYSTEMD_SERVICE_FILE"
}

# Setup logrotate
setup_logrotate() {
    log_step "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
$LOG_FILE {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_USER $SERVICE_GROUP
    postrotate
        /bin/systemctl reload-or-restart $SERVICE_NAME >/dev/null 2>&1 || true
    endscript
}
EOF
    
    log_info "Log rotation configured"
}

# Enable and start service
enable_service() {
    log_step "Configuring systemd service..."
    
    # Reload systemd
    systemctl daemon-reload
    
    # Enable service
    systemctl enable "$SERVICE_NAME"
    
    log_info "Service enabled for automatic startup"
    log_warn "Service is NOT started yet. You must configure $CONFIG_FILE first!"
}

# Cleanup temporary files
cleanup() {
    log_step "Cleaning up temporary files..."
    
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    
    # Clean Go cache
    if [[ -d "/tmp/go-cache" ]]; then
        rm -rf "/tmp/go-cache"
    fi
    
    if [[ -d "/tmp/go" ]]; then
        rm -rf "/tmp/go"
    fi
    
    log_info "Cleanup completed"
}

# Display post-installation instructions
show_instructions() {
    echo
    echo "======================================================================"
    log_info "Argus Ninja Poller installation completed successfully!"
    echo "======================================================================"
    echo
    echo "Next steps:"
    echo
    echo "1. Edit the configuration file:"
    echo "   sudo nano $CONFIG_FILE"
    echo
    echo "2. Required configuration changes:"
    echo "   - Set oauth2.client_id (your NinjaRMM API client ID)"
    echo "   - Set oauth2.client_secret (your NinjaRMM API client secret)"
    echo "   - Set syslog.server (your syslog server address)"
    echo "   - Configure organizations.organization_ids (target org IDs)"
    echo
    echo "3. Test the configuration:"
    echo "   sudo -u $SERVICE_USER $BINARY_PATH $CONFIG_FILE --list-orgs"
    echo
    echo "4. Start the service:"
    echo "   sudo systemctl start $SERVICE_NAME"
    echo
    echo "5. Check service status:"
    echo "   sudo systemctl status $SERVICE_NAME"
    echo
    echo "6. View logs:"
    echo "   sudo journalctl -u $SERVICE_NAME -f"
    echo "   tail -f $LOG_FILE"
    echo
    echo "7. Service management commands:"
    echo "   sudo systemctl start $SERVICE_NAME     # Start service"
    echo "   sudo systemctl stop $SERVICE_NAME      # Stop service"
    echo "   sudo systemctl restart $SERVICE_NAME   # Restart service"
    echo "   sudo systemctl status $SERVICE_NAME    # Check status"
    echo
    echo "Configuration file location: $CONFIG_FILE"
    echo "State file location: $STATE_FILE"
    echo "Log file location: $LOG_FILE"
    echo "Binary location: $BINARY_PATH"
    echo
    echo "For troubleshooting, check the logs and ensure:"
    echo "- Network connectivity to NinjaRMM API and syslog server"
    echo "- Valid API credentials"
    echo "- Correct organization IDs"
    echo "- Syslog server is accepting connections"
    echo
    echo "======================================================================"
}

# Main execution
main() {
    echo "======================================================================"
    echo "Argus Ninja Poller Deployment Script"
    echo "======================================================================"
    echo
    
    # Trap to ensure cleanup on exit
    trap cleanup EXIT
    
    check_root
    check_system
    install_go
    create_service_user
    download_and_compile
    setup_directories
    install_binary
    install_configuration
    create_systemd_service
    setup_logrotate
    enable_service
    
    show_instructions
}

# Run main function
main "$@"
