# Incident Log System

A lightweight web application for managing security incident logs with file attachments, built for Ubuntu deployment on a local area network.

## Features

- **User Authentication**: Secure login system with username/password
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

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Application

```bash
python app.py
```

The application will:
- Create the SQLite database automatically
- Initialize the default admin user
- Start the web server on `http://0.0.0.0:5000`

### 4. Access the Application

Open your web browser and navigate to:
- Local: `http://localhost:5000`
- LAN: `http://<server-ip>:5000`

**Default Login Credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **Important**: Change the default password after first login!

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
│   └── import.html
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

## Security Considerations

### For Production Deployment:

1. **Change the Secret Key**: 
   - Set the `SESSION_SECRET` environment variable
   - Use a strong, random value

2. **Change Default Password**:
   - Login with admin/admin123
   - Create a new admin user with a strong password
   - Delete or disable the default admin account

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
