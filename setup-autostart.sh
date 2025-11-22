#!/bin/bash

# Incident Log System - Auto-Start Setup
# Run this script from your application directory on Ubuntu

set -e

echo "========================================="
echo "Setting up Auto-Start for Incident Log"
echo "========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (use sudo)" 
   exit 1
fi

# Get the current directory (where the app is already deployed)
CURRENT_DIR=$(pwd)
CURRENT_USER=$(stat -c '%U' app.py)

echo ""
echo "Detected application at: $CURRENT_DIR"
echo "Running as user: $CURRENT_USER"
echo ""

# Find Python interpreter
PYTHON_PATH=$(which python3)
echo "Python found at: $PYTHON_PATH"

# Create log directory
LOG_DIR="/var/log/incident-log"
mkdir -p $LOG_DIR
chown $CURRENT_USER:$CURRENT_USER $LOG_DIR

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/incident-log.service"
echo "Creating service file at: $SERVICE_FILE"

cat > $SERVICE_FILE << EOF
[Unit]
Description=Incident Log System
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
Environment="PATH=$CURRENT_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=$PYTHON_PATH $CURRENT_DIR/app.py
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/app.log
StandardError=append:$LOG_DIR/error.log

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

# Enable auto-start on boot
echo "Enabling auto-start on boot..."
systemctl enable incident-log

# Stop manual process if running
echo "Checking for running processes..."
pkill -f "python.*app.py" || true
sleep 2

# Start the service
echo "Starting service..."
systemctl start incident-log

echo ""
echo "========================================="
echo "Auto-Start Setup Complete!"
echo "========================================="
echo ""
echo "Service Status:"
systemctl status incident-log --no-pager || true
echo ""
echo "✅ The application will now automatically start on server reboot!"
echo ""
echo "Useful Commands:"
echo "  Check status:  sudo systemctl status incident-log"
echo "  View logs:     sudo tail -f $LOG_DIR/app.log"
echo "  Restart:       sudo systemctl restart incident-log"
echo "  Stop:          sudo systemctl stop incident-log"
echo ""
