#!/bin/bash

################################################################################
# Incident Log System - Automated Ubuntu Deployment Script
################################################################################
# This script performs a complete deployment from fresh GitHub clone:
# - Installs system dependencies
# - Creates Python virtual environment
# - Installs Python packages
# - Generates SESSION_SECRET automatically
# - Creates systemd service with embedded secrets
# - Enables auto-start on boot
# - Starts the application
#
# Usage: sudo bash deploy-ubuntu.sh
################################################################################

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_DIR=$(pwd)
APP_USER=$(stat -c '%U' .)
SERVICE_NAME="incident-log"
LOG_DIR="/var/log/${SERVICE_NAME}"

################################################################################
# Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BLUE}=========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=========================================${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

################################################################################
# Pre-flight Checks
################################################################################

print_header "Incident Log System - Automated Deployment"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   echo "Usage: sudo bash deploy-ubuntu.sh"
   exit 1
fi

print_info "Application directory: ${APP_DIR}"
print_info "Running as user: ${APP_USER}"

# Check if app.py exists
if [ ! -f "${APP_DIR}/app.py" ]; then
    print_error "app.py not found in current directory"
    echo "Please run this script from the application root directory"
    exit 1
fi

# Check if requirements.txt exists
if [ ! -f "${APP_DIR}/requirements.txt" ]; then
    print_error "requirements.txt not found"
    exit 1
fi

################################################################################
# Step 1: Install System Dependencies
################################################################################

print_header "Step 1: Installing System Dependencies"

print_info "Updating package lists..."
apt update -qq

print_info "Installing Python 3, pip, venv, and OpenSSL..."
apt install -y python3-full python3-venv python3-pip openssl > /dev/null 2>&1

PYTHON_PATH=$(which python3)
PYTHON_VERSION=$(python3 --version)

print_success "Python installed: ${PYTHON_VERSION} at ${PYTHON_PATH}"

################################################################################
# Step 2: Create Virtual Environment
################################################################################

print_header "Step 2: Creating Python Virtual Environment"

VENV_DIR="${APP_DIR}/venv"

if [ -d "$VENV_DIR" ]; then
    print_warning "Virtual environment already exists at ${VENV_DIR}"
    print_info "Removing old virtual environment..."
    rm -rf "$VENV_DIR"
fi

print_info "Creating virtual environment..."
sudo -u $APP_USER python3 -m venv "$VENV_DIR"

print_success "Virtual environment created at ${VENV_DIR}"

################################################################################
# Step 3: Install Python Dependencies
################################################################################

print_header "Step 3: Installing Python Dependencies"

print_info "Installing packages from requirements.txt..."
sudo -u $APP_USER "$VENV_DIR/bin/pip" install --upgrade pip > /dev/null 2>&1
sudo -u $APP_USER "$VENV_DIR/bin/pip" install -r "${APP_DIR}/requirements.txt" > /dev/null 2>&1

INSTALLED_COUNT=$(sudo -u $APP_USER "$VENV_DIR/bin/pip" list | wc -l)
print_success "Installed ${INSTALLED_COUNT} Python packages"

################################################################################
# Step 4: Generate SESSION_SECRET
################################################################################

print_header "Step 4: Generating Secure SESSION_SECRET"

SESSION_SECRET=$(openssl rand -hex 32)

if [ -z "$SESSION_SECRET" ]; then
    print_error "Failed to generate SESSION_SECRET"
    exit 1
fi

print_success "Generated 256-bit SESSION_SECRET: ${SESSION_SECRET:0:16}...${SESSION_SECRET: -8}"

################################################################################
# Step 5: Create Log Directory
################################################################################

print_header "Step 5: Creating Log Directory"

if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
    print_success "Created log directory: ${LOG_DIR}"
else
    print_info "Log directory already exists: ${LOG_DIR}"
fi

chown $APP_USER:$APP_USER "$LOG_DIR"
chmod 755 "$LOG_DIR"

print_success "Log directory permissions set for user ${APP_USER}"

################################################################################
# Step 6: Create Systemd Service
################################################################################

print_header "Step 6: Creating Systemd Service"

SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

print_info "Creating service file: ${SERVICE_FILE}"

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Incident Log System
After=network.target

[Service]
Type=simple
User=${APP_USER}
WorkingDirectory=${APP_DIR}
Environment="PATH=${VENV_DIR}/bin:/usr/local/bin:/usr/bin:/bin"
Environment="SESSION_SECRET=${SESSION_SECRET}"
ExecStart=${VENV_DIR}/bin/python ${APP_DIR}/app.py
Restart=always
RestartSec=10
StandardOutput=append:${LOG_DIR}/app.log
StandardError=append:${LOG_DIR}/error.log

[Install]
WantedBy=multi-user.target
EOF

print_success "Systemd service file created"
print_info "SESSION_SECRET embedded in service file (secure, root-only access)"

################################################################################
# Step 7: Stop Existing Processes
################################################################################

print_header "Step 7: Stopping Existing Processes"

print_info "Checking for running Python processes..."
if pgrep -f "python.*app.py" > /dev/null; then
    print_warning "Found running Python processes, stopping them..."
    pkill -f "python.*app.py" || true
    sleep 2
    print_success "Existing processes stopped"
else
    print_info "No existing processes found"
fi

################################################################################
# Step 8: Enable and Start Service
################################################################################

print_header "Step 8: Enabling and Starting Service"

print_info "Reloading systemd daemon..."
systemctl daemon-reload

print_info "Enabling auto-start on boot..."
systemctl enable $SERVICE_NAME > /dev/null 2>&1

print_info "Starting service..."
systemctl start $SERVICE_NAME

# Wait for service to start
sleep 3

################################################################################
# Step 9: Verify Deployment
################################################################################

print_header "Step 9: Verifying Deployment"

# Check service status
if systemctl is-active --quiet $SERVICE_NAME; then
    print_success "Service is running"
else
    print_error "Service failed to start"
    echo ""
    echo "Check logs with: sudo journalctl -u ${SERVICE_NAME} -n 50"
    exit 1
fi

# Check if auto-start is enabled
if systemctl is-enabled --quiet $SERVICE_NAME; then
    print_success "Auto-start on boot is enabled"
else
    print_warning "Auto-start is not enabled"
fi

# Get server IP address
SERVER_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1)

# Wait a bit more for the app to initialize
sleep 2

# Extract admin password from logs
print_info "Retrieving admin credentials from application logs..."
ADMIN_PASSWORD=""

# Try to get password from app logs (last 100 lines)
if [ -f "${LOG_DIR}/app.log" ]; then
    ADMIN_PASSWORD=$(tail -n 100 "${LOG_DIR}/app.log" | grep -oP 'Password: \K[^\s]+' | tail -n 1)
fi

################################################################################
# Final Success Message
################################################################################

print_header "🎉 Deployment Complete!"

echo ""
echo -e "${GREEN}=================================================================================${NC}"
echo -e "${GREEN}                    Incident Log System - Ready!${NC}"
echo -e "${GREEN}=================================================================================${NC}"
echo ""
echo -e "${BLUE}📍 Application URL:${NC}"
echo "   Local:  http://localhost:5000"
if [ -n "$SERVER_IP" ]; then
    echo "   LAN:    http://${SERVER_IP}:5000"
fi
echo ""
echo -e "${BLUE}🔑 Admin Credentials:${NC}"
echo "   Username: admin"
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "   Password: ${ADMIN_PASSWORD}"
else
    echo "   Password: Check logs → sudo tail -f ${LOG_DIR}/app.log"
    echo "             Look for 'IMPORTANT: Default admin user created'"
fi
echo ""
echo -e "${YELLOW}⚠️  SAVE THE PASSWORD NOW - It will not be shown again!${NC}"
echo ""
echo -e "${GREEN}=================================================================================${NC}"
echo ""
echo -e "${BLUE}✅ Service Status:${NC}"
systemctl status $SERVICE_NAME --no-pager -l | grep -E "Loaded|Active|Main PID" || true
echo ""
echo -e "${BLUE}📋 Useful Commands:${NC}"
echo "   Check status:    sudo systemctl status ${SERVICE_NAME}"
echo "   View app logs:   sudo tail -f ${LOG_DIR}/app.log"
echo "   View errors:     sudo tail -f ${LOG_DIR}/error.log"
echo "   Restart service: sudo systemctl restart ${SERVICE_NAME}"
echo "   Stop service:    sudo systemctl stop ${SERVICE_NAME}"
echo ""
echo -e "${BLUE}🔄 Auto-Start:${NC}"
echo "   ✅ The application will automatically start after server reboots"
echo "   ✅ The application will restart automatically if it crashes"
echo ""
echo -e "${BLUE}📁 File Locations:${NC}"
echo "   Application:  ${APP_DIR}"
echo "   Database:     ${APP_DIR}/instance/incidents.db"
echo "   Uploads:      ${APP_DIR}/uploads/"
echo "   Logs:         ${LOG_DIR}/"
echo "   Service:      ${SERVICE_FILE}"
echo ""
echo -e "${GREEN}🎯 Next Steps:${NC}"
echo "   1. Access the application in your browser"
echo "   2. Log in with the admin credentials above"
echo "   3. Change the admin password immediately"
echo "   4. Configure backup settings (Backup → Backup Settings)"
echo "   5. Add additional users if needed (Users → Add New User)"
echo ""
echo -e "${GREEN}=================================================================================${NC}"
echo ""

# Final health check
print_info "Performing final health check..."
if curl -s http://localhost:5000 > /dev/null 2>&1; then
    print_success "Application is responding to HTTP requests"
else
    print_warning "Application may still be starting up (wait 10 seconds and try accessing)"
fi

echo ""
print_success "Deployment complete! Your incident log system is ready to use."
echo ""

exit 0
