# Ubuntu Server Deployment Guide

## Automatic Startup Configuration

This guide explains how to deploy the Incident Log System on Ubuntu Server with automatic startup on boot.

## Prerequisites

- Ubuntu Server (18.04 or later)
- Python 3.8 or higher
- Root/sudo access
- Application files copied to server

## Quick Deployment

### 1. Copy Files to Ubuntu Server

Transfer all application files to your Ubuntu server using one of these methods:

```bash
# Using SCP
scp -r /path/to/incident-log user@server-ip:/tmp/

# Using rsync
rsync -avz /path/to/incident-log user@server-ip:/tmp/

# Or clone from Git
git clone <your-repo-url> /tmp/incident-log
```

### 2. Run Deployment Script

```bash
cd /tmp/incident-log
sudo chmod +x deploy.sh
sudo ./deploy.sh
```

The script will:
- ✅ Create application directory at `/opt/incident-log`
- ✅ Set up Python virtual environment
- ✅ Install all dependencies
- ✅ Configure systemd service
- ✅ Enable automatic startup on boot
- ✅ Start the application

### 3. Verify Installation

```bash
# Check service status
sudo systemctl status incident-log

# View live logs
sudo journalctl -u incident-log -f

# Test the application
curl http://localhost:5000
```

## Service Management

### Starting/Stopping the Service

```bash
# Start
sudo systemctl start incident-log

# Stop
sudo systemctl stop incident-log

# Restart
sudo systemctl restart incident-log

# Check status
sudo systemctl status incident-log
```

### Viewing Logs

```bash
# System logs (via journalctl)
sudo journalctl -u incident-log -f

# Application logs
sudo tail -f /var/log/incident-log/app.log

# Error logs
sudo tail -f /var/log/incident-log/error.log
```

### Enable/Disable Auto-Start

```bash
# Enable auto-start on boot (default)
sudo systemctl enable incident-log

# Disable auto-start
sudo systemctl disable incident-log
```

## Configuration

### Environment Variables

Create a `.env` file in `/opt/incident-log/`:

```bash
sudo nano /opt/incident-log/.env
```

Add your environment variables:

```env
SESSION_SECRET=your-secret-key-here
SMB_USERNAME=your-smb-username
SMB_PASSWORD=your-smb-password
```

Then restart the service:

```bash
sudo systemctl restart incident-log
```

### Firewall Configuration

Allow access to port 5000:

```bash
sudo ufw allow 5000/tcp
sudo ufw reload
```

### Nginx Reverse Proxy (Optional)

For production, use Nginx as a reverse proxy:

```bash
sudo apt install nginx

# Create Nginx configuration
sudo nano /etc/nginx/sites-available/incident-log
```

Add this configuration:

```nginx
server {
    listen 80;
    server_name your-server-ip-or-domain;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable and restart Nginx:

```bash
sudo ln -s /etc/nginx/sites-available/incident-log /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status incident-log

# View detailed logs
sudo journalctl -u incident-log -n 100 --no-pager

# Check file permissions
ls -la /opt/incident-log
```

### Database Issues

```bash
# Check database file permissions
ls -la /opt/incident-log/instance/incidents.db

# Fix permissions if needed
sudo chown -R www-data:www-data /opt/incident-log/instance
```

### Port Already in Use

```bash
# Check what's using port 5000
sudo lsof -i :5000

# Kill the process if needed
sudo kill <PID>

# Or change the port in app.py
```

## Backup Considerations

The automated backup system will run according to your configured schedule. Ensure:

1. **SMB credentials** are properly configured in the database or environment variables
2. **Network share** is accessible from the Ubuntu server
3. **Service is running** for scheduled backups to execute

Test your backup:
```bash
# Monitor logs during scheduled backup time
sudo journalctl -u incident-log -f
```

## Security Recommendations

1. **Change default admin password** immediately after deployment
2. **Use HTTPS** with Nginx and SSL certificate (Let's Encrypt)
3. **Restrict port 5000** to localhost if using Nginx reverse proxy
4. **Regular updates**: Keep Ubuntu and Python packages updated
5. **Backup database** regularly to the configured SMB share

## Updating the Application

```bash
# Stop the service
sudo systemctl stop incident-log

# Update code
cd /opt/incident-log
sudo -u www-data git pull  # If using git

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Restart service
sudo systemctl start incident-log
```

## Complete Removal

```bash
# Stop and disable service
sudo systemctl stop incident-log
sudo systemctl disable incident-log

# Remove service file
sudo rm /etc/systemd/system/incident-log.service
sudo systemctl daemon-reload

# Remove application
sudo rm -rf /opt/incident-log
sudo rm -rf /var/log/incident-log
```

## Support

For issues or questions, refer to the main application documentation or system logs.
