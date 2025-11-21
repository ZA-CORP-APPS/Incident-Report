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
- **UI/UX**: Clean Bootstrap 5 design with color-coded severity (Low=Green, Medium=Yellow, High=Orange, Critical=Red) and status badges. Intuitive navigation and flash messages for user feedback.
- **Authentication & Authorization**: Secure login, session management, role-based access control (Admin/User), and comprehensive user management with admin-only functionalities for adding, viewing, deleting, and resetting passwords for users. Robust security features like brute-force protection (5 attempts, 15-minute lockout) and required `SESSION_SECRET`.
- **Incident Management**: Full CRUD operations for incidents, including auto-generated IDs, timestamping, camera location, severity, description, persons involved, actions taken, footage reference, reporting/reviewing personnel, remarks, and secure file attachments (JPG/BMP, max 16MB).
- **Reporting**: Multi-incident report generation with extensive filtering capabilities (date range, severity, camera location, reported by, reviewed by, persons involved, description). Reports are optimized for print and PDF export with a professional layout and filter summary.
- **Data Handling**: Export/import functionality for incident data in JSON and CSV formats, with server-side validation for data integrity during import.
- **Audit Logging**: Admin-only audit history logging for all incident creation, update, and deletion actions, including user, timestamp, action type, and incident details.
- **Application Settings**: Admin-only functionality to upload an app-wide logo, displayed in the navigation bar.
- **File Management**: Secure file uploads with validation, sanitization, and timestamped filenames.

## External Dependencies
- **Python Libraries**: Listed in `requirements.txt` (e.g., Flask, SQLAlchemy, Flask-Login, Werkzeug).
- **Frontend Framework**: Bootstrap 5 (loaded via CDN).
- **Database**: SQLite (built-in, file-based).