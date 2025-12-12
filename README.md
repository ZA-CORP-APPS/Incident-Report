# Incident Log System

A comprehensive, lightweight web application for managing security and safety incident logs with extensive file attachment support, built for Ubuntu deployment on a local area network (LAN).

## Features

### 🔐 Authentication & User Management
- **Secure Login System**: Username/password authentication with session management
- **Role-Based Access Control**: Admin and User roles with appropriate permissions
- **User Management (Admin Only)**:
  - Add/remove users
  - Reset user passwords
  - View all user accounts with role badges
  - Protected admin accounts (cannot be deleted)
- **Password Security**:
  - Secure password hashing (pbkdf2:sha256)
  - Brute-force protection (5 attempts, 15-minute lockout)
  - Self-service password change for all users
  - Strong password generation for admin accounts

### 📋 Incident Management
- **Dynamic Incident Type Classification**: Admin-customizable incident types (defaults to Security and Safety)
  - Create unlimited custom incident types via Admin menu
  - Configure color and optional emoji icon per type
  - Deactivate types without data loss (historical data preserved)
  - All incident types automatically available in forms and reports
- **Comprehensive Data Fields**:
  - Auto-generated incident ID
  - Date and time of incident
  - Incident type (Security/Safety)
  - Camera location with autocomplete
  - Detailed incident description
  - Persons involved
  - Action taken
  - Footage reference
  - Reported by (auto-filled)
  - Reviewed by
  - Remarks/outcome
  - Review status tracking
- **Full CRUD Operations**: Create, Read, Update, Delete incidents
- **Dashboard Sorting**: Sort incidents by date/time (ascending or descending)
- **Search & Filter**: Quick search across all incident fields

### 📁 File Attachments
- **Multiple File Support**: Attach multiple files per incident
- **Supported Formats**:
  - Images: JPG, JPEG, BMP
  - Videos: MP4, AVI, MOV
- **Storage Capacity**: Up to 1GB total per incident
- **File Management**:
  - Individual file download
  - Download all attachments as ZIP bundle
  - Inline image preview
  - HTML5 video player for video files
  - Multi-folder file selection with queue system
  - Upload progress indicator for large files
  - File size display and validation

### 📊 Analytics Dashboard
- **Visual Statistics** powered by Chart.js:
  - Incidents by month (last 12 months)
  - Incidents by all custom types (dynamically populated)
  - Severity distribution
  - Review status breakdown
  - Top 10 camera locations
  - Yearly trends
  - Monthly type breakdown with dynamic type comparison
- **Real-Time Updates**: All charts reflect current database state and automatically adapt to new incident types
- **Interactive Charts**: Hover for detailed information
- **Dynamic Adaptation**: No configuration needed - analytics automatically handle any number of custom incident types

### 📑 Reporting
- **Multi-Incident Reports**: Generate comprehensive reports with extensive filtering
- **Filter Options**:
  - Date range (from/to)
  - Incident type (Security/Safety/All)
  - Severity level
  - Camera location
  - Reported by
  - Reviewed by
  - Persons involved
  - Description keywords
- **Print & PDF Ready**: Optimized layout for professional reports
- **Image Thumbnails**: Reports include 150px image previews
- **Filter Summary**: Shows applied filters at the top of reports

### 🔍 Audit History
- **Comprehensive Tracking**: All incident changes logged
- **Audit Details**:
  - User who made the change
  - Timestamp of action
  - Action type (Created/Updated/Deleted)
  - Incident details snapshot
- **Persistence**: Audit logs remain even after incident deletion
- **Pagination**: 50 logs per page for performance
- **Admin-Only Access**: Restricted to administrators

### 💾 Data Management
- **Export Formats**:
  - JSON: Complete data with attachment metadata
  - CSV: Tabular format with attachment count
- **Import Capability**:
  - Restore from JSON or CSV files
  - Server-side validation
  - Automatic error handling for invalid records
- **Incident Type Support**: Export/import includes incident classification

### 🔄 Automated Backup & Restore System
- **Backup Destinations**:
  - Local filesystem (mounted shares)
  - **SMB/CIFS Network Shares** (Windows/Samba servers)
- **Scheduled Backups**:
  - Configurable frequency (Daily/Weekly/Monthly)
  - Custom time selection
  - Automatic retention management
- **Backup Features**:
  - Secure SQLite snapshots (sqlite3.Connection.backup API)
  - tar.gz compression
  - SHA256 checksums for integrity verification
  - Organized structure: `<destination>/incident_backups/YYYY/MM/timestamp/`
  - Metadata tracking (version, file counts, checksums)
- **Restore Operations**:
  - Browse available backups
  - Pre-restore safety backup
  - Complete database and file restoration
  - Integrity verification before restore
- **Backup Job History**:
  - Track all backup/restore operations
  - Success/failure status
  - Detailed error messages
  - User attribution

### 🌐 SMB/CIFS Network Share Integration
- **Direct Network Connectivity**: Connect to Windows/Samba shares without mounting
- **SMB Configuration**:
  - Server hostname or IP address
  - Share name
  - Port (default: 445)
  - Domain (optional)
- **Secure Credential Management**:
  - Credentials stored as environment secrets
  - Never stored in database
  - `SMB_USERNAME` and `SMB_PASSWORD` environment variables
- **Connection Testing**: Test SMB connectivity before saving configuration
- **Modern Protocol Support**: SMBv2/SMBv3 via smbprotocol library
- **Dual Mode**: Seamlessly switch between local filesystem and SMB shares
- **Thread-Safe Operations**: Concurrent backup operations with RLock

### 🎨 Application Settings
- **Custom Logo Upload** (Admin Only):
  - Upload organization logo (JPG/BMP)
  - Displayed in navigation bar (40px height)
  - Automatic cleanup of old logos
  - Branding across all pages

### 🎨 User Interface
- **Clean Bootstrap 5 Design**: Professional, responsive layout
- **Customizable Color-Coded Indicators**:
  - Severity: Low (Green), Medium (Yellow), High (Orange), Critical (Red)
  - Incident Type: Customizable colors and icons (Security Blue, Safety Yellow by default)
  - Status: Pending (Warning), Reviewed (Success)
- **Intuitive Navigation**: Easy access to all features
- **Flash Messages**: Real-time user feedback
- **Mobile Responsive**: Works on desktop, tablet, and mobile devices

## Technology Stack

- **Backend**: Python 3.11+ with Flask 3.0.0
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login with secure password hashing (Werkzeug)
- **Frontend**: Bootstrap 5, HTML5, CSS3, JavaScript
- **Charts**: Chart.js for analytics visualizations
- **File Handling**: Werkzeug secure file uploads
- **Backup**: APScheduler for automated scheduling
- **Network Shares**: smbprotocol for SMB/CIFS connectivity
- **Compression**: Python tarfile and hashlib for backups

## Requirements

- **Operating System**: Ubuntu 20.04+ (or any modern Linux distribution)
- **Python**: 3.11 or higher
- **Disk Space**: 500MB minimum (more for file attachments and backups)
- **Web Browser**: Modern browser (Chrome, Firefox, Edge, Safari)
- **Network**: LAN connectivity for multi-user access
- **Optional**: SMB/CIFS network share for remote backups

## 🚀 Quick Installation (Ubuntu Production Deployment)

### Automated One-Command Deployment

For production Ubuntu LAN servers with **automatic startup on boot**:

```bash
# Clone to your preferred location
git clone <your-github-repo-url> /home/lulo/Incident-Report
cd /home/lulo/Incident-Report

# Run automated deployment script
sudo bash deploy-ubuntu.sh
```

**That's it!** The script automatically:
- ✅ Installs all system dependencies
- ✅ Creates Python virtual environment  
- ✅ Installs Python packages
- ✅ Generates secure SESSION_SECRET
- ✅ Creates systemd service with auto-start on boot
- ✅ Starts the application immediately
- ✅ Displays admin credentials and access URL

**📖 For complete deployment instructions, see [DEPLOYMENT.md](DEPLOYMENT.md)**

---

## 💻 Manual Installation (Development/Testing)

If you prefer manual setup or are running on non-Ubuntu systems:

### 1. Clone the Repository

```bash
git clone <repository-url>
cd incident-log-system
```

### 2. Create a Virtual Environment

```bash
# Install python3-venv if not already installed
sudo apt install python3-full python3-venv

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Set the required `SESSION_SECRET` environment variable:

```bash
# Generate a secure random secret
export SESSION_SECRET="$(openssl rand -hex 32)"

# For SMB/CIFS backup support (optional)
export SMB_USERNAME="your_smb_username"
export SMB_PASSWORD="your_smb_password"
```

**Note**: This is temporary. For production, use the automated deployment which stores SESSION_SECRET securely in the systemd service.

### 5. Run the Application

```bash
python app.py
```

The application will:
- Create the SQLite database automatically (`instance/incidents.db`)
- Initialize the default admin user with a secure random password
- Start the backup scheduler
- Start the web server on `http://0.0.0.0:5000`

### 6. Access the Application

Open your web browser and navigate to:
- **Local**: `http://localhost:5000`
- **LAN**: `http://<server-ip>:5000` (find IP with `ip addr show`)

### 7. Initial Login

On first startup, the application generates a secure random password for the admin user and displays it in the console:

```
================================================================================
IMPORTANT: Default admin user created
================================================================================
Username: admin
Password: <randomly-generated-secure-password>
================================================================================
SECURITY WARNING: Save this password now! It will not be shown again.
Please change this password immediately after first login.
================================================================================
```

⚠️ **Critical**: Save this password immediately - it will not be displayed again!

---

## 🔄 Production Deployment with Auto-Start

For production Ubuntu servers, **always use the automated deployment script** instead of manual installation. This ensures:

- ✅ Application survives server reboots
- ✅ Automatic restart if application crashes  
- ✅ Proper systemd service management
- ✅ Secure SESSION_SECRET storage
- ✅ Centralized logging to `/var/log/incident-log/`

See **[DEPLOYMENT.md](DEPLOYMENT.md)** for complete production deployment guide.

## Project Structure

```
incident-log-system/
├── app.py                      # Main Flask application (single-file)
├── requirements.txt            # Python dependencies
├── README.md                   # This documentation
├── replit.md                   # Technical architecture notes
├── .gitignore                  # Git ignore rules
├── instance/                   # SQLite database (auto-created)
│   └── incidents.db
├── uploads/                    # File attachments and logos
│   ├── logo_*.jpg              # App logo (if uploaded)
│   └── <timestamped_files>     # Incident attachments
├── templates/                  # HTML templates
│   ├── base.html               # Base template with navigation
│   ├── login.html              # Login page
│   ├── dashboard.html          # Main incident dashboard
│   ├── incident_form.html      # Create/edit incident form
│   ├── incident_view.html      # Incident details view
│   ├── analytics.html          # Analytics dashboard
│   ├── report.html             # Multi-incident report
│   ├── import.html             # Data import page
│   ├── users.html              # User management
│   ├── add_user.html           # Add new user form
│   ├── change_password.html    # Change password form
│   ├── reset_password.html     # Reset user password
│   ├── audit_history.html      # Audit log viewer
│   ├── settings.html           # App settings (logo upload)
│   ├── backup_settings.html    # Backup configuration
│   └── backup_management.html  # Backup/restore interface
└── static/                     # Static assets
    └── css/
        └── style.css           # Custom CSS styles
```

## Usage Guide

### Creating an Incident Log

1. Click **"New Incident"** button on the dashboard
2. Fill in the incident details:
   - **Incident Type**: Select from custom types (managed in Admin → Incident Types)
   - **Date & Time**: Select when incident occurred (required)
   - **Camera Location**: Enter location (autocomplete enabled)
   - **Severity**: Choose Low, Medium, High, or Critical
   - **Description**: Detailed description (required)
   - **Persons Involved**: Names or identifiers
   - **Action Taken**: Response actions
   - **Footage Reference**: Camera footage details
   - **Reviewed By**: Reviewing officer
   - **Remarks**: Additional notes or outcome
3. **Add Files** (optional):
   - Click "Add Files" button (can be clicked multiple times for different folders)
   - Select images (JPG/BMP) or videos (MP4/AVI/MOV)
   - Files accumulate in queue with size display
   - Remove individual files if needed
   - Total size must not exceed 1GB
4. Click **"Create Incident"**

### Viewing Incidents

- **Dashboard**: Shows all incidents in sortable table
- **Sort by Date**: Click "Earliest First" or "Latest First" toggle buttons
- **Color Badges**:
  - Incident Type: Color-coded per custom type configuration
  - Severity: Green (Low), Yellow (Medium), Orange (High), Red (Critical)
  - Status: Yellow (Pending), Green (Reviewed)
- **View Details**: Click eye icon to see full incident with attachments
- **Search**: Use search box to filter by any field
- **Inactive Types**: Incidents with deactivated types still display correctly

### Managing Attachments

When viewing an incident:
- **View Images**: Thumbnails displayed inline
- **Play Videos**: HTML5 player with controls
- **Download Individual File**: Click filename to download
- **Download All**: Click "Download All as ZIP" button
- **File Info**: Size and type displayed for each file

### Editing/Deleting Incidents

- **Edit**: Click pencil icon, modify fields, save changes
- **Delete**: Click "Delete" button when viewing incident
  - Confirmation required
  - Deletes incident, all attachments, and creates audit log
  - Audit log preserved for compliance

### Analytics Dashboard

Access via **"Analytics"** menu:
- View incident trends and statistics
- **Summary Cards**: Display counts for all incident types automatically
- **Incident Type Chart**: Pie chart of all custom types with dynamic colors
- **Monthly Trends**: Line chart showing trends across all custom types
- **Interactive Charts**: Hover for detailed information
- Charts update automatically with new data and new incident types
- Filter by clicking chart elements
- **No Configuration Needed**: Add new incident types and charts adapt automatically

### Generating Reports

1. Click **"Reports"** in navigation menu
2. **Set Filters**:
   - Date range (optional)
   - Incident type (Security/Safety/All)
   - Severity level
   - Camera location
   - Personnel names
   - Description keywords
3. Click **"Generate Report"**
4. **Print or Save as PDF**:
   - Use browser print function (Ctrl+P or Cmd+P)
   - Select "Save as PDF" as printer
   - Professional layout optimized for printing
   - Includes filter summary and image thumbnails

### Audit History (Admin Only)

Access via **"Audit History"** menu:
- View all incident changes
- See who made changes and when
- Review deleted incident snapshots
- Navigate through pages (50 logs per page)

### Managing Incident Types (Admin Only)

Access via **"Admin"** → **"Incident Types"**:

**Create New Type**:
1. Click **"Add New Type"**
2. Enter incident type name (e.g., "Equipment Failure", "Environmental")
3. Select Bootstrap color (primary, success, warning, danger, info, etc.)
4. Add optional emoji icon (e.g., ⚙️, 🌡️, 🔥)
5. Click **"Create Type"**

**Manage Existing Types**:
- **Edit**: Modify name, color, or icon
- **Deactivate**: Hide from new incidents while preserving historical data
- **Delete**: Remove types (data not affected)
- All incident forms and reports automatically update

**Notes**:
- New types appear in all incident dropdowns immediately
- Incidents with deactivated types can still be viewed and edited
- Backward compatible: existing incidents retain their types

### User Management (Admin Only)

Access via **"Users"** menu:

**Add New User**:
1. Click **"Add New User"**
2. Enter username, full name, password
3. Assign role (Admin or User)
4. Click **"Add User"**

**Manage Existing Users**:
- **View Users**: See all accounts with role badges
- **Reset Password**: Generate new password for users (not admins)
- **Delete User**: Remove user accounts (not admins)
- **Protected Accounts**: Admin accounts cannot be deleted by other admins

### Changing Your Password

All users can change their own password:
1. Click your username in navigation
2. Select **"Change Password"**
3. Enter current password
4. Enter new password (minimum 8 characters)
5. Confirm new password
6. Click **"Change Password"**

### Exporting Data

1. Click **"Export/Import"** in navigation
2. Choose format:
   - **Export to JSON**: Complete data with attachment metadata
   - **Export to CSV**: Spreadsheet-compatible format
3. File downloads automatically

### Importing Data

1. Click **"Export/Import"** → **"Import Data"**
2. Upload JSON or CSV file (must match export format)
3. Review results:
   - Success count
   - Skipped records (if any)
   - Error details
4. **Note**: File attachments are not imported, only metadata

### Configuring Backups

#### For Local Filesystem Backups:

1. Click **"Backup"** → **"Backup Settings"**
2. Ensure **"Use SMB/CIFS Network Share"** is unchecked
3. Configure:
   - **Shared Folder Path**: `/mnt/backup` or mounted network path
   - **Enable Scheduled Backups**: Check to enable
   - **Schedule Frequency**: Daily, Weekly, or Monthly
   - **Backup Time**: HH:MM (24-hour format)
   - **Retention Count**: Number of backups to keep (default: 7)
4. Click **"Save Settings"**

#### For SMB/CIFS Network Share Backups:

1. **Set Environment Secrets** (one-time setup):
   ```bash
   export SMB_USERNAME="your_network_username"
   export SMB_PASSWORD="your_network_password"
   ```

2. Click **"Backup"** → **"Backup Settings"**
3. Check **"Use SMB/CIFS Network Share"**
4. Configure SMB settings:
   - **SMB Server**: `192.168.1.100` or `fileserver.local`
   - **Share Name**: `backups` (share name without backslashes)
   - **Port**: `445` (default SMB port)
   - **Domain**: Leave empty unless required by your network
5. Click **"Test Connection"** to verify settings
6. Configure backup schedule (same as local filesystem)
7. Click **"Save Settings"**

**Backup Location**: Backups are stored in:
- Local: `<shared_folder>/incident_backups/YYYY/MM/timestamp/`
- SMB: `\\server\share\incident_backups\YYYY\MM\timestamp/`

### Managing Backups

Access via **"Backup"** → **"Manage Backups"**:

**Manual Backup**:
- Click **"Backup Now"** to create immediate backup
- Status appears in job history

**View Backup History**:
- See last 50 backup/restore operations
- Status: Success (green) or Failed (red)
- Details: timestamp, incident count, file count, size

**Restore from Backup**:
1. Browse **"Available Backups"** section
2. Select desired backup from list
3. Click **"Restore"** button
4. Confirm restoration
5. **Pre-restore safety backup created automatically**
6. Application reloads with restored data

**Backup Contents**:
- Complete SQLite database
- All uploaded files (attachments and logos)
- Metadata with checksums for integrity verification

### Application Settings (Admin Only)

Access via **"Settings"** menu:

**Upload Logo**:
1. Click **"Choose File"**
2. Select JPG or BMP image
3. Click **"Upload Logo"**
4. Logo appears in navigation bar (40px height)
5. Old logo automatically deleted

## Security Features

### Authentication & Authorization
- **Strong Password Generation**: 20-character random passwords for admin
- **Login Attempt Tracking**: 5 attempts max, 15-minute lockout
- **Session Management**: Secure Flask-Login sessions
- **Password Hashing**: Industry-standard pbkdf2:sha256
- **Role-Based Access**: Admin and User roles with restrictions
- **Protected Accounts**: Admins cannot delete themselves or other admins
- **Session Secret**: Required `SESSION_SECRET` environment variable

### File Security
- **File Type Validation**: Only JPG, JPEG, BMP, MP4, AVI, MOV allowed
- **Size Limits**: 1GB total per incident
- **Filename Sanitization**: Secure filename handling with Werkzeug
- **Timestamped Filenames**: Prevents collisions and overwrites

### Backup Security
- **SMB Credentials**: Stored as environment secrets, never in database
- **Checksum Verification**: SHA256 for backup integrity
- **Path Validation**: Prevents directory traversal attacks
- **Pre-restore Backup**: Safety backup before restoration
- **Audit Trail**: All backup/restore operations logged

### Network Security
- **LAN Deployment**: Designed for internal network use
- **Firewall Protection**: Run behind firewall, restrict port 5000
- **Reverse Proxy**: Consider nginx/Apache for HTTPS in production
- **Access Control**: Role-based restrictions on sensitive operations

## Required Environment Variables

### SESSION_SECRET (REQUIRED)
```bash
# Generate secure random secret
export SESSION_SECRET="$(openssl rand -hex 32)"
```

### SMB Credentials (Optional - for SMB backup)
```bash
export SMB_USERNAME="your_network_username"
export SMB_PASSWORD="your_network_password"
```

**Persistent Configuration**: Add to `~/.bashrc` or systemd service file:
```bash
echo 'export SESSION_SECRET="<your-secret>"' >> ~/.bashrc
echo 'export SMB_USERNAME="<username>"' >> ~/.bashrc
echo 'export SMB_PASSWORD="<password>"' >> ~/.bashrc
source ~/.bashrc
```

## Configuration

### Application Settings (in app.py)

- **MAX_CONTENT_LENGTH**: 1GB (1073741824 bytes)
- **ALLOWED_EXTENSIONS**: jpg, jpeg, bmp, mp4, avi, mov
- **Port**: 5000 (change in last line of `app.py`)
- **Debug Mode**: Enabled by default (disable for production)
- **Database**: SQLite at `instance/incidents.db`
- **Upload Folder**: `uploads/`

### Backup Configuration

Configured via web UI (**Backup** → **Backup Settings**):
- Backup frequency (daily/weekly/monthly)
- Backup time (24-hour format)
- Retention count (number of backups to keep)
- Destination (local path or SMB share)

## Troubleshooting

### Application won't start

```bash
# Check Python version
python --version  # Should be 3.11 or higher

# Check SESSION_SECRET is set
echo $SESSION_SECRET  # Should output a value

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Check for errors in console output
python app.py
```

### SESSION_SECRET error

```bash
# Set SESSION_SECRET
export SESSION_SECRET="$(openssl rand -hex 32)"

# Verify it's set
echo $SESSION_SECRET

# Run application
python app.py
```

### Can't access from other computers on LAN

```bash
# Check firewall rules
sudo ufw status
sudo ufw allow 5000

# Verify server IP address
ip addr show

# Test from another machine
ping <server-ip>
curl http://<server-ip>:5000
```

### Database errors

```bash
# Backup existing database
cp instance/incidents.db instance/incidents.db.backup

# Reset database (WARNING: Deletes all data)
rm -rf instance/incidents.db

# Restart application (will recreate database)
python app.py
```

### File upload fails

```bash
# Check uploads folder exists and has permissions
ls -la uploads/
chmod 755 uploads/

# Check file size (must be under 1GB total per incident)
# Check file format (JPG, JPEG, BMP, MP4, AVI, MOV only)

# Check disk space
df -h
```

### Backup fails (Local filesystem)

```bash
# Check shared folder exists
ls -la /path/to/shared/folder

# Check write permissions
touch /path/to/shared/folder/test.txt
rm /path/to/shared/folder/test.txt

# Check disk space on backup destination
df -h /path/to/shared/folder
```

### Backup fails (SMB share)

```bash
# Verify environment variables are set
echo $SMB_USERNAME
echo $SMB_PASSWORD

# Test SMB connection (requires smbclient)
sudo apt install smbclient
smbclient //server/share -U username

# Check SMB server is accessible
ping <smb-server-ip>
telnet <smb-server-ip> 445

# Review backup job history for error details
# Check via web UI: Backup → Manage Backups
```

### SMB connection test fails

**Common issues**:
1. **Incorrect credentials**: Verify `SMB_USERNAME` and `SMB_PASSWORD`
2. **Firewall blocking**: Ensure port 445 is open
3. **Share permissions**: User must have write access to share
4. **Network connectivity**: Ping SMB server, check network
5. **Domain authentication**: Add domain if required by server

### Scheduler not running

```bash
# Check console output for scheduler errors
# Scheduler starts automatically with application

# Verify backup is enabled in settings
# Check via web UI: Backup → Backup Settings

# Check backup job history
# View via web UI: Backup → Manage Backups
```

## Production Deployment

### Systemd Service (Ubuntu)

Create `/etc/systemd/system/incident-log.service`:

```ini
[Unit]
Description=Incident Log System
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/incident-log
Environment="SESSION_SECRET=<your-secret-here>"
Environment="SMB_USERNAME=<your-smb-username>"
Environment="SMB_PASSWORD=<your-smb-password>"
ExecStart=/opt/incident-log/venv/bin/python /opt/incident-log/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable incident-log
sudo systemctl start incident-log
sudo systemctl status incident-log
```

### Reverse Proxy (nginx)

For HTTPS and better performance, use nginx:

```nginx
server {
    listen 80;
    server_name incidents.yourcompany.local;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # For large file uploads
        client_max_body_size 1G;
        proxy_read_timeout 600s;
    }
}
```

### Production Checklist

- [ ] Set strong `SESSION_SECRET` in environment
- [ ] Set `debug=False` in `app.py`
- [ ] Configure automated backups
- [ ] Set up systemd service for auto-start
- [ ] Configure firewall rules
- [ ] Set up nginx reverse proxy (optional but recommended)
- [ ] Enable HTTPS with SSL certificate
- [ ] Test backup and restore procedures
- [ ] Document admin password in secure location
- [ ] Configure log rotation
- [ ] Set up monitoring and alerts

## Data Backup Best Practices

1. **Automated Backups**: Enable scheduled backups (daily recommended)
2. **Retention Policy**: Keep at least 7 backups (configurable)
3. **Remote Storage**: Use SMB share to store backups off-system
4. **Regular Testing**: Periodically test restore procedures
5. **Multiple Locations**: Consider copying backups to multiple locations
6. **Monitoring**: Check backup job history regularly for failures

## License

This project is provided as-is for internal use.

## Contributing

For bugs, feature requests, or contributions, please contact the system administrator or check the repository issues.

## Version History

- **v1.0.0** (November 2025): Initial release
- **v1.1.0** (November 2025): Added incident type classification, multiple attachments
- **v1.2.0** (November 2025): Added analytics dashboard, audit logging, app settings
- **v1.3.0** (November 2025): Added backup/restore system with SMB/CIFS support

## Support

For technical support, feature requests, or bug reports, please check the GitHub repository or contact your system administrator.

---

**Current Version**: 1.3.0  
**Last Updated**: November 22, 2025  
**Maintained By**: System Administrator
