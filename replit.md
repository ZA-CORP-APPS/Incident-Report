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
│   ├── import.html       # Data import page
│   ├── users.html        # User management (admin only)
│   ├── add_user.html     # Add new user form (admin only)
│   ├── change_password.html # Change own password
│   └── reset_password.html # Reset user password (admin only)
└── static/                # Static assets
    └── css/
        └── style.css     # Custom CSS styling
```

## Core Features Implemented

### 1. User Authentication & Management
- Secure login system with username/password
- Session management with Flask-Login
- Password hashing using Werkzeug
- Role-based access control (Admin/User roles)
- **Admin-Only User Management**:
  - Add new users with username, full name, password, and role assignment
  - View all users with their roles (Admin/User badges)
  - Delete non-admin users (admins are protected from deletion)
  - Reset passwords for non-admin users
- **Password Management**:
  - All users can change their own password (requires current password)
  - Password requirements: minimum 8 characters
  - Password confirmation validation
- **Security Controls**:
  - Admins cannot delete themselves or other admin users
  - Admins cannot reset passwords of other admin users
  - Admin users must use self-service password change
  - Protected admin accounts shown with "Protected" badge in UI
- Default admin account created on first launch with randomly generated strong password (shown in console)

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
- `is_admin` (Boolean, Default: False)
- `failed_login_attempts` (Integer, Default: 0)
- `locked_until` (DateTime, Nullable)

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

## Security Features (Production-Ready)
- **Required SESSION_SECRET**: Application refuses to start without environment variable set
- **Strong Password Generation**: Admin password randomly generated (20 chars: letters/digits/symbols)
- **Brute-Force Protection**: 5-attempt limit with 15-minute lockout on failed logins
- **Password Hashing**: Werkzeug pbkdf2:sha256 algorithm
- **Session Management**: Secure session cookies with Flask-Login
- **File Upload Security**: Strict validation and sanitization (JPG/BMP only, 16MB limit)
- **SQL Injection Protection**: SQLAlchemy ORM with parameterized queries
- **Secure Filename Handling**: Werkzeug secure_filename() for all uploads

**Security Review Status**: ✅ Architect-reviewed and approved for production LAN deployment

## Known Configuration
- Workflow configured: "Start Application" runs `python app.py`
- Output type: webview on port 5000
- Auto-creates database and default admin user on first run
- Auto-creates necessary directories (instance/, uploads/)

## Recent Changes
- **2025-11-21**: User management system added and security hardening completed
  - **User Management Features** (Architect-reviewed and approved):
    - Added is_admin field to User model for role-based access control
    - Created admin_required decorator for protecting admin-only routes
    - Implemented add user functionality (admin only) with role assignment
    - Implemented user listing with role badges and action buttons
    - Implemented delete user functionality (prevents deleting admins)
    - Implemented password change for all users (requires current password)
    - Implemented admin password reset for non-admin users only
    - Updated navigation menu with "Users" link (admin only) and "Change Password" option
    - Added admin badge display in navigation menu
    - Created 4 new templates: users.html, add_user.html, change_password.html, reset_password.html
  - **Security Controls** (All architect-verified):
    - Admin users cannot be deleted (enforced at backend and UI level)
    - Admin passwords cannot be reset by other admins (only self-service change)
    - Password confirmation validation enforced before saving
    - All password changes require minimum 8 characters
    - UI shows "Protected" badge for admin users
    - No privilege escalation vulnerabilities

- **2025-11-21**: Initial project creation and security hardening
  - Implemented complete Flask application with all CRUD operations
  - Created all database models and routes
  - Built responsive Bootstrap UI with Bootstrap 5
  - Added export/import functionality (JSON and CSV)
  - Configured workflow for port 5000
  - Fixed database path to use absolute paths
  - **Security Improvements** (Architect-reviewed and approved):
    - Required SESSION_SECRET environment variable (app refuses to start without it)
    - Implemented strong random password generation for admin user (20 characters)
    - Added login attempt tracking with 5-attempt limit and 15-minute lockout
    - All security gaps remediated and production-ready for LAN deployment

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
