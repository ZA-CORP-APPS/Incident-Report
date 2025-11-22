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
- **UI/UX**: Clean Bootstrap 5 design with color-coded severity (Low=Green, Medium=Yellow, High=Orange, Critical=Red), incident type badges (Security=Blue, Safety=Yellow), and status badges. Dashboard features date/time sorting with Asc/Desc toggle buttons (earliest first by default). Intuitive navigation and flash messages for user feedback.
- **Authentication & Authorization**: Secure login, session management, role-based access control (Admin/User), and comprehensive user management with admin-only functionalities for adding, viewing, deleting, and resetting passwords for users. Robust security features like brute-force protection (5 attempts, 15-minute lockout) and required `SESSION_SECRET`.
- **Incident Management**: Full CRUD operations for incidents, including incident type classification (Security/Safety), auto-generated IDs, timestamping, camera location, severity, description, persons involved, actions taken, footage reference, reporting/reviewing personnel, remarks, and multiple secure file attachments supporting images (JPG/BMP) and videos (MP4/AVI/MOV) up to 1GB total per incident.
- **File Attachments**: Multiple file upload system using IncidentAttachment model with relationship to Incident table. Files are stored with metadata (filename, size, type). Individual file download or download all attachments as ZIP bundle. Legacy single-attachment field maintained for backwards compatibility.
- **Analytics**: Comprehensive analytics dashboard with Chart.js visualizations displaying real-time statistics and trends including: incidents by month (last 12 months), incidents by type (Security vs Safety), severity distribution, review status, top 10 camera locations, yearly trends, and monthly type breakdown. All charts are interactive and responsive.
- **Reporting**: Multi-incident report generation with extensive filtering capabilities (date range, incident type, severity, camera location, reported by, reviewed by, persons involved, description). Reports are optimized for print and PDF export with a professional layout and filter summary.
- **Data Handling**: Export/import functionality for incident data in JSON and CSV formats, with server-side validation for data integrity during import. Both formats include incident_type field and attachment metadata (CSV includes attachment count, JSON includes full attachment details).
- **Audit Logging**: Comprehensive admin-only audit history system with transactional integrity. Tracks all incident creation, update, and deletion actions with user, timestamp, action type, and incident details. Key design decisions: (1) AuditLog.incident_id has NO foreign key constraint, allowing logs to persist after incident deletion for compliance; (2) Description snapshots stored in audit logs for deleted incidents; (3) Single-transaction commits ensure either both audit log and incident change succeed or both fail; (4) Pagination (50 logs per page) prevents performance issues; (5) File deletion happens before DB transaction (acceptable since filesystem operations cannot be rolled back).
- **Application Settings**: Admin-only functionality to upload an app-wide logo (JPG/BMP), displayed in the navigation bar at 40px height. Automatic cleanup removes old logo files when uploading new ones. Settings stored in AppSettings model using key-value pairs. Context processor makes logo available across all templates.
- **File Management**: Secure file uploads with validation, sanitization, and timestamped filenames. Maximum upload size: 1GB per incident.

## Recent Changes (2025-11-22)
- **Report Image Thumbnails**: Added image thumbnails (150px) and video placeholders to generated reports for better visualization
- **File Upload UX**: Added instructions for selecting multiple files (Ctrl/Cmd+Click), file list preview, and upload progress indicator for large files (>5MB)
- **Bug Fixes**: Resolved video upload display issue - videos now properly save and display (issue was browser file selection, not upload functionality)

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