# Auto-Start Setup for Ubuntu

Since your app is already deployed on Ubuntu, this guide shows you how to make it start automatically on server reboot.

## Quick Setup (One Command)

From your application directory on Ubuntu:

```bash
sudo chmod +x setup-autostart.sh
sudo ./setup-autostart.sh
```

That's it! Your app will now:
- ✅ Start automatically when the server boots
- ✅ Restart automatically if it crashes
- ✅ Keep running in the background

## What the Script Does

1. Detects your current application directory
2. Creates a systemd service file
3. Enables auto-start on boot
4. Stops any manual `python app.py` processes
5. Starts the service

## Manual Setup (If Preferred)

If you prefer to set it up manually:

### 1. Create the service file

```bash
sudo nano /etc/systemd/system/incident-log.service
```

Add this content (adjust paths to match your setup):

```ini
[Unit]
Description=Incident Log System
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/your/app
ExecStart=/usr/bin/python3 /path/to/your/app/app.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/incident-log/app.log
StandardError=append:/var/log/incident-log/error.log

[Install]
WantedBy=multi-user.target
```

### 2. Enable and start the service

```bash
# Create log directory
sudo mkdir -p /var/log/incident-log

# Reload systemd
sudo systemctl daemon-reload

# Enable auto-start
sudo systemctl enable incident-log

# Start the service
sudo systemctl start incident-log

# Check status
sudo systemctl status incident-log
```

## Managing the Service

```bash
# Check if running
sudo systemctl status incident-log

# View logs
sudo tail -f /var/log/incident-log/app.log

# Restart
sudo systemctl restart incident-log

# Stop
sudo systemctl stop incident-log

# Disable auto-start (if needed)
sudo systemctl disable incident-log
```

## Testing Auto-Start

To verify it works after reboot:

```bash
# Reboot the server
sudo reboot

# After reboot, SSH back in and check
sudo systemctl status incident-log
```

The service should be running automatically!

## Troubleshooting

### Service won't start

```bash
# Check detailed status
sudo systemctl status incident-log -l

# View recent logs
sudo journalctl -u incident-log -n 50
```

### Port already in use

If you get "port 5000 already in use":

```bash
# Find the process
sudo lsof -i :5000

# Kill your manual python process
pkill -f "python.*app.py"

# Restart the service
sudo systemctl restart incident-log
```

### Permission issues

```bash
# Check file ownership
ls -la /path/to/your/app

# Fix if needed (replace USERNAME)
sudo chown -R USERNAME:USERNAME /path/to/your/app
```

## Removing Auto-Start

If you want to go back to manual start:

```bash
# Stop and disable
sudo systemctl stop incident-log
sudo systemctl disable incident-log

# Remove service file
sudo rm /etc/systemd/system/incident-log.service
sudo systemctl daemon-reload
```

Then you can use `python app.py` manually again.
