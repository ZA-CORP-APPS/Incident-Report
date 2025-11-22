#!/bin/bash

# Incident Log System - Ubuntu Deployment Script
# This script sets up the application to auto-start on server reboot

set -e

echo "========================================="
echo "Incident Log System - Deployment Setup"
echo "========================================="

# Configuration
APP_DIR="/opt/incident-log"
SERVICE_NAME="incident-log"
LOG_DIR="/var/log/incident-log"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root (use sudo)" 
   exit 1
fi

echo ""
echo "Step 1: Creating application directory..."
mkdir -p $APP_DIR
mkdir -p $LOG_DIR

echo "Step 2: Copying application files..."
cp -r . $APP_DIR/
cd $APP_DIR

echo "Step 3: Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "Step 4: Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Step 5: Creating database directory..."
mkdir -p instance
mkdir -p uploads

echo "Step 6: Setting permissions..."
chown -R www-data:www-data $APP_DIR
chown -R www-data:www-data $LOG_DIR
chmod -R 755 $APP_DIR
chmod -R 755 $LOG_DIR

echo "Step 7: Installing systemd service..."
cp incident-log.service /etc/systemd/system/
systemctl daemon-reload

echo "Step 8: Enabling auto-start on boot..."
systemctl enable $SERVICE_NAME

echo "Step 9: Starting the service..."
systemctl start $SERVICE_NAME

echo ""
echo "========================================="
echo "Deployment Complete!"
echo "========================================="
echo ""
echo "Service Status:"
systemctl status $SERVICE_NAME --no-pager
echo ""
echo "Useful Commands:"
echo "  Start service:   sudo systemctl start $SERVICE_NAME"
echo "  Stop service:    sudo systemctl stop $SERVICE_NAME"
echo "  Restart service: sudo systemctl restart $SERVICE_NAME"
echo "  View status:     sudo systemctl status $SERVICE_NAME"
echo "  View logs:       sudo journalctl -u $SERVICE_NAME -f"
echo "  View app log:    sudo tail -f $LOG_DIR/app.log"
echo ""
echo "The application will now automatically start on server reboot!"
echo "Access the application at: http://YOUR_SERVER_IP:5000"
echo ""
