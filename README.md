# Incident Log System

A lightweight web application for managing security incident logs with file attachments, built for Ubuntu deployment on a local area network.

## Features

- **User Authentication & Management**: 
  - Secure login system with username/password
  - Role-based access control (Admin/User)
  - Admins can add/remove users and manage passwords
  - All users can change their own password
  - Brute-force protection with account lockout
- **Incident Management**: Create, view, edit, and delete incident logs
- **Comprehensive Data Fields**:
  - Auto-generated incident ID
  - Date and time of incident
  - Camera location
  - Detailed incident description
  - Persons involved
  - Action taken
  - Footage reference
  - Reported by
  - Reviewed by
  - Remarks/outcome
- **File Attachments**: Upload and manage image files (JPG/BMP) up to 16MB
- **Search & Filter**: Quick search across incident records
- **Data Export**: Export database to JSON or CSV formats for backup
- **Data Import**: Restore data from JSON or CSV files
- **Responsive UI**: Clean, professional Bootstrap-based interface

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login with secure password hashing
- **Frontend**: Bootstrap 5, HTML5, CSS3
- **File Handling**: Werkzeug secure file uploads

## Requirements

- Python 3.11 or higher
- Ubuntu (tested) or any Linux distribution
- 100MB disk space (minimum)
- Modern web browser (Chrome, Firefox, Edge)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd <repository-directory>
```

### 2. Create a Virtual Environment (Ubuntu 22.04+)

Modern Ubuntu requires virtual environments for Python packages:

```bash
# Install python3-venv if not already installed
sudo apt install python3-full python3-venv

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate
```

### 3. Install Python Dependencies

With the virtual environment activated:

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

The application will:
- Create the SQLite database automatically
- Initialize the default admin user
- Start the web server on `http://0.0.0.0:5000`

### 5. Access the Application

Open your web browser and navigate to:
- Local: `http://localhost:5000`
- LAN: `http://<server-ip>:5000`

**Initial Login Credentials:**

On first startup, the application will generate a secure random password for the admin user and display it in the console output. Look for output like this:

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

⚠️ **Critical**: Save the password immediately - it will not be displayed again!

## Project Structure

```
incident-log-system/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── .gitignore             # Git ignore rules
├── instance/              # SQLite database (auto-created)
│   └── incidents.db
├── uploads/               # File attachments storage
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── incident_form.html
│   ├── incident_view.html
│   ├── import.html
│   ├── users.html
│   ├── add_user.html
│   ├── change_password.html
│   └── reset_password.html
└── static/                # Static assets
    └── css/
        └── style.css
```

## Usage Guide

### Creating an Incident Log

1. Click **"New Incident"** button
2. Fill in the incident details:
   - Date & Time (required)
   - Camera Location
   - Incident Description (required)
   - Persons Involved
   - Action Taken
   - Footage Reference
   - Reported By (auto-filled with your name)
   - Reviewed By
   - Remarks/Outcome
3. Optionally upload an image (JPG/BMP, max 16MB)
4. Click **"Create Incident"**

### Viewing Incidents

- Dashboard shows all incidents in a table format
- Use the search box to filter incidents
- Click the **eye icon** to view full details
- Review status is indicated with color badges

### Editing/Deleting Incidents

- Click the **pencil icon** to edit an incident
- Click **"Delete"** button when viewing an incident (requires confirmation)

### Exporting Data

1. Click **"Export/Import"** in the navigation menu
2. Choose **"Export to JSON"** or **"Export to CSV"**
3. File will be downloaded automatically

### Importing Data

1. Click **"Export/Import"** → **"Import Data"**
2. Upload a JSON or CSV file (must match export format)
3. Invalid records will be skipped automatically

### User Management (Admin Only)

Administrators can manage user accounts:

1. Click **"Users"** in the navigation menu
2. **Add New User**:
   - Click **"Add New User"** button
   - Enter username, full name, and password
   - Assign Admin or User role
   - Click **"Add User"**
3. **View Users**: See all users with their roles (Admin/User badges)
4. **Reset Password**: Click **"Reset Password"** button for non-admin users
5. **Delete User**: Click **"Delete"** button for non-admin users
6. **Protected Accounts**: Admin users cannot be deleted or have passwords reset by other admins

### Changing Your Password

All users can change their own password:

1. Click your username in the navigation menu
2. Select **"Change Password"**
3. Enter your current password
4. Enter and confirm your new password (minimum 8 characters)
5. Click **"Change Password"**

## Security Features

The application includes several built-in security features:

### Authentication Security
- **Strong Password Generation**: Admin password is randomly generated with 20 characters (letters, numbers, symbols)
- **Login Attempt Tracking**: Maximum 5 failed login attempts before 15-minute account lockout
- **Session Management**: Secure session cookies with Flask-Login
- **Password Hashing**: Industry-standard password hashing with Werkzeug (pbkdf2:sha256)
- **Role-Based Access Control**: Admin and User roles with appropriate permission restrictions
- **Admin Protection**: Admin users cannot delete themselves or other admins
- **Password Security**: Admins can only reset passwords for non-admin users

### Required Security Configuration

1. **Session Secret (REQUIRED)**: 
   - The `SESSION_SECRET` environment variable must be set
   - Application will refuse to start without it
   - Use a strong, cryptographically random value
   - Example: `export SESSION_SECRET="$(openssl rand -hex 32)"`

2. **Admin Password Management**:
   - Randomly generated on first startup
   - Displayed once in console output
   - Must be saved immediately
   - Change password after first login for additional security

3. **File Upload Security**:
   - Only JPG and BMP files are allowed
   - File size limited to 16MB
   - Filenames are sanitized automatically

4. **Database Backup**:
   - Regularly export data using the export function
   - Back up the `instance/incidents.db` file
   - Back up the `uploads/` folder

5. **Network Security**:
   - Use firewall rules to restrict access to port 5000
   - Consider using a reverse proxy (nginx/Apache) for HTTPS
   - Run behind a firewall on your LAN

## Troubleshooting

### Application won't start

```bash
# Check Python version
python --version  # Should be 3.11 or higher

# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

### Can't access from other computers on LAN

- Check firewall rules: `sudo ufw allow 5000`
- Verify the server IP address: `ip addr show`
- Ensure the application is binding to `0.0.0.0` (default)

### Database errors

```bash
# Reset database (WARNING: Deletes all data)
rm -rf instance/incidents.db
python app.py  # Will recreate database
```

### File upload fails

- Check `uploads/` folder permissions: `chmod 755 uploads/`
- Verify file size is under 16MB
- Ensure file format is JPG or BMP

## Configuration

### Environment Variables

- `SESSION_SECRET`: Secret key for session encryption (recommended for production)

### Application Settings (in app.py)

- `MAX_CONTENT_LENGTH`: Maximum upload file size (default: 16MB)
- `ALLOWED_EXTENSIONS`: Allowed file types (default: jpg, jpeg, bmp)
- Port: Default 5000 (change in the last line of app.py)

## Backup and Restore

### Manual Backup

```bash
# Backup database
cp instance/incidents.db backup_$(date +%Y%m%d).db

# Backup uploads
tar -czf uploads_backup_$(date +%Y%m%d).tar.gz uploads/
```

### Restore from Backup

```bash
# Restore database
cp backup_YYYYMMDD.db instance/incidents.db

# Restore uploads
tar -xzf uploads_backup_YYYYMMDD.tar.gz
```

### Using Built-in Export/Import

1. Export to JSON (includes all incident data)
2. Import the JSON file to restore on a new installation
3. Note: File attachments must be backed up separately

## Development

### Running in Debug Mode

Debug mode is enabled by default. For production:

Edit `app.py`, change the last line:
```python
app.run(host='0.0.0.0', port=5000, debug=False)
```

### Adding New Users (via Python shell)

```python
from app import app, db, User

with app.app_context():
    user = User(username='newuser', full_name='New User')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()
```

## License

This project is provided as-is for internal use.

## Support

For issues, bugs, or feature requests, please check the GitHub repository or contact the system administrator.

---

**Version**: 1.0.0  
**Last Updated**: November 2025
