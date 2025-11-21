# Incident Log System

## Project Overview
A lightweight web application for managing security incident logs with file attachments, authentication, and data export/import capabilities. Built for Ubuntu deployment on a local area network (LAN) with a single PC setup.

## Technology Stack
- **Backend**: Python 3.11 with Flask 3.0.0
- **Database**: SQLite with SQLAlchemy ORM
- **Authentication**: Flask-Login with secure password hashing
- **Frontend**: Bootstrap 5, HTML5, CSS3
- **File Handling**: Werkzeug secure file uploads

## Project Structure
```
incident-log-system/
├── app.py                  # Main Flask application with all routes and logic
├── requirements.txt        # Python dependencies
├── README.md              # Comprehensive setup and usage guide
├── .gitignore             # Git ignore rules
├── replit.md              # Project documentation (this file)
├── instance/              # SQLite database storage (created at runtime)
│   └── incidents.db
├── uploads/               # Image attachments storage
├── templates/             # HTML Jinja2 templates
│   ├── base.html         # Base template with navigation
│   ├── login.html        # Login page
│   ├── dashboard.html    # Main incident list view
│   ├── incident_form.html # Create/edit incident form
│   ├── incident_view.html # View incident details
│   └── import.html       # Data import page
└── static/                # Static assets
    └── css/
        └── style.css     # Custom CSS styling
```

## Core Features Implemented

### 1. User Authentication
- Secure login system with username/password
- Session management with Flask-Login
- Password hashing using Werkzeug
- Default admin account: username `admin`, password `admin123`

### 2. Incident Management
Complete CRUD operations for incident logs with the following fields:
- **Auto-generated ID**: Primary key, auto-incremented
- **Date & Time**: Timestamp of incident occurrence
- **Camera Location**: Location identifier
- **Incident Description**: Detailed text description (required)
- **Persons Involved**: Names/descriptions of individuals
- **Action Taken**: Response actions documented
- **Footage Reference**: Reference to video footage
- **Reported By**: Name of person reporting (auto-filled from logged-in user)
- **Reviewed By**: Name of reviewer
- **Remarks/Outcome**: Final notes and resolution
- **File Attachments**: Image uploads (JPG/BMP, max 16MB)
- **Metadata**: Created at and updated at timestamps

### 3. Search & Filter
- Real-time search across incident descriptions, camera locations, persons involved, and reporter names
- Clear search functionality
- Results displayed in responsive table format

### 4. File Management
- Secure file upload with validation
- Supported formats: JPG, JPEG, BMP
- Maximum file size: 16MB
- Automatic filename sanitization
- Timestamped filenames to prevent conflicts
- View and download attachments
- Automatic cleanup when incidents are deleted

### 5. Data Export/Import
- **Export to JSON**: Complete incident data with timestamps
- **Export to CSV**: Spreadsheet-compatible format
- **Import from JSON**: Restore data from JSON backups
- **Import from CSV**: Bulk import capability
- Error handling for invalid data formats

### 6. User Interface
- Clean, professional Bootstrap 5 design
- Responsive layout for desktop use
- Color-coded status badges (Reviewed/Pending)
- Confirmation dialogs for destructive actions
- Flash messages for user feedback
- Intuitive navigation menu
- Custom styling with professional color scheme

## Database Schema

### User Table
- `id` (Integer, Primary Key)
- `username` (String, Unique, Required)
- `password_hash` (String, Required)
- `full_name` (String)

### Incident Table
- `id` (Integer, Primary Key)
- `incident_datetime` (DateTime, Required)
- `camera_location` (String)
- `incident_description` (Text, Required)
- `persons_involved` (Text)
- `action_taken` (Text)
- `footage_reference` (String)
- `reported_by` (String)
- `reviewed_by` (String)
- `remarks_outcome` (Text)
- `attachment_filename` (String)
- `created_at` (DateTime, Auto)
- `updated_at` (DateTime, Auto)

## Configuration
- **Secret Key**: Uses `SESSION_SECRET` environment variable or default for development
- **Database Path**: Absolute path to `instance/incidents.db`
- **Upload Folder**: Absolute path to `uploads/` directory
- **Port**: 5000 (configured for webview)
- **Host**: 0.0.0.0 (accessible from LAN)
- **Debug Mode**: Enabled for development

## Deployment Details
- **Target Platform**: Ubuntu Linux
- **Deployment Type**: Single PC on LAN
- **Dependencies**: All listed in requirements.txt
- **Database**: Self-contained SQLite (no external DB server needed)
- **File Storage**: Local filesystem
- **GitHub Integration**: Connected and ready for repository push

## Security Features
- Password hashing with Werkzeug (pbkdf2:sha256)
- Session management with secure cookies
- File upload validation and sanitization
- SQL injection protection via SQLAlchemy ORM
- CSRF protection through Flask's built-in features
- Secure filename handling

## Known Configuration
- Workflow configured: "Start Application" runs `python app.py`
- Output type: webview on port 5000
- Auto-creates database and default admin user on first run
- Auto-creates necessary directories (instance/, uploads/)

## Recent Changes
- **2025-11-21**: Initial project creation
  - Implemented complete Flask application
  - Created all database models and routes
  - Built responsive Bootstrap UI
  - Added export/import functionality
  - Configured workflow for port 5000
  - Fixed database path to use absolute paths
  - Successfully tested and verified application running

## User Preferences
- Clean, professional UI without excessive complexity
- Lightweight and self-contained solution
- No external dependencies beyond standard Python libraries
- Focus on reliability and ease of use
- Ubuntu/LAN deployment ready

## Next Steps (Future Enhancements)
- User role management (admin, reviewer, reporter)
- Incident status workflow (draft, submitted, under review, closed)
- Email notifications for assignments
- PDF report generation
- Audit trail logging
- Password change functionality
- User management interface
- Advanced filtering and sorting options
- Dashboard statistics and charts

## Architecture Notes
- Single-file application (app.py) for simplicity
- Templates use Jinja2 inheritance for consistency
- SQLAlchemy ORM for database abstraction
- Flask-Login for session management
- Bootstrap CDN for frontend (no local dependencies)
- Static assets served by Flask development server

## Default Credentials
⚠️ **Important**: Change these after first login
- Username: `admin`
- Password: `admin123`

## GitHub Repository
- GitHub integration: Connected
- Ready for initial repository push
- .gitignore configured to exclude database, uploads, and Python cache files
