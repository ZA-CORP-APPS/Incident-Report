# Incident Log System

## Overview
A lightweight, self-contained web application designed for managing security incident logs within a local area network (LAN) on a single Ubuntu PC. Its primary purpose is to provide a comprehensive system for recording, tracking, and reporting security incidents, complete with file attachments, robust authentication, and data export/import capabilities. The project aims for a clean, professional UI, focusing on reliability and ease of use, and is architect-approved for production LAN deployment.

## User Preferences
- Clean, professional UI without excessive complexity
- Lightweight and self-contained solution
- No external dependencies beyond standard Python libraries
- Focus on reliability and ease of use
- Ubuntu/LAN deployment ready

## System Architecture
The system is built as a single-file Flask application (`app.py`) for simplicity, using Python 3.11 and Flask 3.0.0. It employs SQLite with SQLAlchemy ORM for database management, storing data in `instance/incidents.db` and attachments in an `uploads/` directory. Authentication is handled by Flask-Login with secure password hashing (Werkzeug). The frontend utilizes Bootstrap 5, HTML5, and CSS3 for a responsive and intuitive user interface, featuring color-coded severity and status badges.

Key architectural decisions and features include:
- **UI/UX**: Clean Bootstrap 5 design with color-coded severity (Low=Green, Medium=Yellow, High=Orange, Critical=Red), customizable incident type badges with admin-configurable colors and icons, and status badges. Dashboard features date/time sorting with Asc/Desc toggle buttons (earliest first by default). Intuitive navigation and flash messages for user feedback.
- **Authentication & Authorization**: Secure login, session management, role-based access control (Admin/User), and comprehensive user management with admin-only functionalities for adding, viewing, deleting, and resetting passwords for users. Robust security features like brute-force protection (5 attempts, 15-minute lockout) and required `SESSION_SECRET`.
- **Incident Management**: Full CRUD operations for incidents, including dynamic incident type classification (admin-customizable; defaults to Security/Safety), auto-generated IDs, timestamping, camera location, severity, description, persons involved, actions taken, footage reference, reporting/reviewing personnel, remarks, and multiple secure file attachments supporting images (JPG/BMP) and videos (MP4/AVI/MOV) up to 1GB total per incident.
- **File Attachments**: Multiple file upload system using IncidentAttachment model with relationship to Incident table. Files are stored with metadata (filename, size, type). Individual file download or download all attachments as ZIP bundle. Legacy single-attachment field maintained for backwards compatibility.
- **Analytics**: Comprehensive analytics dashboard with Chart.js visualizations displaying real-time statistics and trends including: incidents by month (last 12 months), incidents by all custom types (dynamically populated), severity distribution, review status, top 10 camera locations, yearly trends, and monthly type breakdown. All charts are interactive, responsive, and automatically adapt to any number of custom incident types.
- **Reporting**: Multi-incident report generation with extensive filtering capabilities (date range, incident type, severity, camera location, reported by, reviewed by, persons involved, description). Reports are optimized for print and PDF export with a professional layout and filter summary.
- **Data Handling**: Export/import functionality for incident data in JSON and CSV formats, with server-side validation for data integrity during import. Both formats include incident_type field and attachment metadata (CSV includes attachment count, JSON includes full attachment details).
- **Audit Logging**: Comprehensive admin-only audit history system with transactional integrity. Tracks all incident creation, update, and deletion actions with user, timestamp, action type, and incident details. Key design decisions: (1) AuditLog.incident_id has NO foreign key constraint, allowing logs to persist after incident deletion for compliance; (2) Description snapshots stored in audit logs for deleted incidents; (3) Single-transaction commits ensure either both audit log and incident change succeed or both fail; (4) Pagination (50 logs per page) prevents performance issues; (5) File deletion happens before DB transaction (acceptable since filesystem operations cannot be rolled back).
- **Application Settings**: Admin-only functionality to upload an app-wide logo (JPG/BMP), displayed in the navigation bar at 40px height. Automatic cleanup removes old logo files when uploading new ones. Settings stored in AppSettings model using key-value pairs. Context processor makes logo available across all templates.
- **File Management**: Secure file uploads with validation, sanitization, and timestamped filenames. Maximum upload size: 1GB per incident.

## Recent Changes (2025-12-12)
- **Custom Incident Types**: Implemented admin-controlled custom incident types replacing hardcoded Security/Safety options:
  - **IncidentType Model**: New database model with name, color, icon, is_active, display_order fields
  - **Admin Management UI**: Full CRUD operations for incident types via Admin menu -> Incident Types
  - **Dynamic Dropdowns**: All incident forms and reports now use database-driven type selection
  - **Customizable Badges**: Each type has configurable Bootstrap color and optional emoji icon
  - **Inactive Types**: Types can be deactivated without deletion (hidden from new incidents but preserved in historical data)
  - **Backwards Compatible**: Existing incidents retain their types; editing incidents with inactive types preserves the original type
  - **Migration Script**: update-incident-types.py safely adds the new table to production databases
  - **Context Processor**: get_incident_types() and get_incident_type_info() available in all templates
- **Analytics Function Fix**: Updated analytics dashboard to handle all custom incident types dynamically:
  - **Dynamic Type Statistics**: Replaced hardcoded Security/Safety counting with database-driven type enumeration
  - **Flexible Summary Cards**: Summary statistics cards now display counts for all active incident types automatically
  - **Dynamic Charts**: Incident type pie chart and monthly trends chart render all custom types with auto-assigned colors
  - **Robust Fallback**: Analytics function includes exception handling to fall back to default Security/Safety if database issues occur
  - **Production Ready**: No changes needed to analytics when adding new incident types; charts adapt automatically

## Recent Changes (2025-11-22)
- **Automated Ubuntu Deployment**: Created comprehensive deployment system for production Ubuntu servers with one-command setup:
  - **deploy-ubuntu.sh**: Fully automated deployment script that handles dependencies, virtual environment, SESSION_SECRET generation, systemd service creation with embedded secrets, and automatic startup on boot
  - **DEPLOYMENT.md**: Complete production deployment guide with troubleshooting, service management, and post-deployment checklist
  - **Systemd Integration**: Application runs as a service with automatic restart on crash, survives server reboots, and includes centralized logging to /var/log/incident-log/
  - **Secure Secret Management**: SESSION_SECRET automatically generated (256-bit) and stored securely in systemd service file (root-only access)
  - **Zero Manual Configuration**: Single command deploys entire stack from fresh GitHub clone with all security properly configured
  - **Deployment Location**: Standard deployment at /home/lulo/Incident-Report/ with service running as lulo user
- **SMB/CIFS Network Share Support**: Added direct SMB/CIFS network share connectivity for backup system. Features include:
  - Direct connection to Windows/Samba network shares without mounting
  - SMB configuration in backup settings (server, share, port, domain)
  - **Dual-mode credential storage**: Database (encrypted with Fernet) OR environment variables (SMB_USERNAME, SMB_PASSWORD)
  - Priority-based credential retrieval: Database credentials take precedence over environment variables
  - Fernet symmetric encryption using SESSION_SECRET-derived key (PBKDF2HMAC with SHA256, 100k iterations)
  - Proper error handling: Encryption/decryption failures raise ValueError with logging, preventing silent fallback
  - Credential source transparency: Flash messages and logs indicate whether credentials came from database or environment
  - Test connection functionality to verify SMB settings before saving
  - Thread-safe backup operations with RLock for concurrent request handling
  - Support for both local mounted folders and direct SMB connections
  - Toggle between local path and SMB mode in admin UI
  - Configuration status card shows current mode, destination, and backup schedule details
  - Uses smbprotocol library for modern SMBv2/SMBv3 support
  - Security warnings in UI clearly indicate database storage is for low-risk LAN environments only
- **Backup & Restore System**: Implemented comprehensive automated backup system with scheduled backups to shared LAN folders. Features include:
  - Admin UI for configuring shared folder path, backup schedule (daily/weekly/monthly), and retention policies
  - Automated backups using APScheduler with configurable time and frequency
  - Secure SQLite backup using sqlite3.Connection.backup() API for consistent snapshots
  - tar.gz compression with SHA256 checksums for data integrity verification
  - Organized backup structure: `<shared_folder>/incident_backups/YYYY/MM/timestamp/`
  - Each backup includes backup.tar.gz and metadata.json with version, checksums, file counts
  - Manual backup trigger from admin UI
  - Complete restore functionality with pre-restore safety backup
  - Backup job history tracking with success/failure status
  - Automatic cleanup of old backups based on retention count
  - BackupConfig and BackupJob database models for configuration and audit trail
- **Report Image Thumbnails**: Added image thumbnails (150px) and video placeholders to generated reports for better visualization
- **Multi-Folder File Upload**: Implemented file queue system with "Add Files" button that can be clicked multiple times to select files from different folders. Files accumulate in a visual queue with remove capability before upload.
- **Upload Progress Indicator**: Switched to Fetch API for asynchronous file uploads with immediate visual progress feedback during large file uploads
- **File Upload UX**: Added file list preview showing all queued files with individual file sizes, total size badge, and ability to remove files before submission
- **Filename Wrapping**: Fixed long filename overflow issue with proper word-wrap CSS in incident view

## Recent Changes (2025-11-21)
- **Incident Type Classification**: Added incident_type field (Security/Safety) to Incident model with color-coded badges throughout UI
- **Multiple File Attachments**: Implemented IncidentAttachment model supporting multiple images (JPG/BMP) and videos (MP4/AVI/MOV) per incident with 1GB total limit
- **Dashboard Sorting**: Added date/time sorting with Asc/Desc toggle buttons, defaults to earliest first
- **Download ZIP Feature**: Created download all attachments route that bundles incident files into ZIP archive
- **Enhanced Incident View**: Updated incident view page to display incident type badge and all attachments with preview (images displayed, videos with HTML5 player)
- **Delete Enhancement**: Updated delete route to properly clean up all multiple attachments and files
- **Analytics Dashboard**: Created comprehensive analytics page with Chart.js visualizations showing incidents by month, year, type, severity, status, and location
- **Export/Import Updates**: Updated JSON and CSV export/import functionality to handle incident_type field and attachment metadata
- **Report Filter Enhancement**: Added incident_type filter to multi-incident report generation with comprehensive filtering
- **Audit Logging System**: Added comprehensive audit history tracking all incident changes with transactional integrity
- **Logo Upload Feature**: Added admin-only app-wide logo upload with automatic file cleanup
- **Navigation Updates**: Added "Audit History", "Settings", and "Analytics" links in navigation
- **Transactional Integrity**: Fixed all audit logging to use single-transaction commits for atomicity
- **FK Constraint Removal**: Removed foreign key constraint from AuditLog.incident_id to allow logs to persist after incident deletion
- **Description Snapshots**: Added incident_description field to audit logs for deleted incidents
- **Pagination**: Added pagination to audit history (50 logs per page) for performance

## External Dependencies
- **Python Libraries**: Listed in `requirements.txt` (e.g., Flask, SQLAlchemy, Flask-Login, Werkzeug).
- **Frontend Framework**: Bootstrap 5 (loaded via CDN).
- **Database**: SQLite (built-in, file-based).

## Admin Credentials
- **Username**: admin
- **Password**: -w]aa#,dM)!J#<4=7E~f