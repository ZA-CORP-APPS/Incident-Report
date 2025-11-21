import os
import json
import csv
import secrets
import string
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO

app = Flask(__name__)

if not os.environ.get('SESSION_SECRET'):
    raise RuntimeError(
        "SESSION_SECRET environment variable is required for security. "
        "Please set SESSION_SECRET before starting the application."
    )

app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'incidents.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max upload
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'bmp', 'mp4', 'avi', 'mov'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class IncidentAttachment(db.Model):
    """Stores multiple file attachments for each incident"""
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10))  # image, video
    file_size = db.Column(db.Integer)  # Size in bytes
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_type = db.Column(db.String(20), default='Security')  # Security or Safety
    incident_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    camera_location = db.Column(db.String(200))
    severity = db.Column(db.String(20), default='Low')
    incident_description = db.Column(db.Text, nullable=False)
    persons_involved = db.Column(db.Text)
    action_taken = db.Column(db.Text)
    footage_reference = db.Column(db.String(200))
    reported_by = db.Column(db.String(120))
    reviewed_by = db.Column(db.String(120))
    remarks_outcome = db.Column(db.Text)
    attachment_filename = db.Column(db.String(255))  # Legacy field for backward compatibility
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    attachments = db.relationship('IncidentAttachment', backref='incident', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'incident_type': self.incident_type,
            'incident_datetime': self.incident_datetime.isoformat() if self.incident_datetime else None,
            'camera_location': self.camera_location,
            'severity': self.severity,
            'incident_description': self.incident_description,
            'persons_involved': self.persons_involved,
            'action_taken': self.action_taken,
            'footage_reference': self.footage_reference,
            'reported_by': self.reported_by,
            'reviewed_by': self.reviewed_by,
            'remarks_outcome': self.remarks_outcome,
            'attachment_filename': self.attachment_filename,
            'attachments': [{'id': a.id, 'filename': a.filename, 'file_type': a.file_type} for a in self.attachments],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class AuditLog(db.Model):
    """Tracks all changes to incidents for admin audit trail"""
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, nullable=False)  # No FK constraint - allows logs to persist after incident deletion
    action = db.Column(db.String(20), nullable=False)  # 'created', 'updated', 'deleted'
    user = db.Column(db.String(80), nullable=False)  # Username who made the change
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.Text)  # Optional details about what changed
    incident_description = db.Column(db.Text)  # Snapshot of description for deleted incidents


class AppSettings(db.Model):
    """Stores application-wide settings like logo"""
    id = db.Column(db.Integer, primary_key=True)
    setting_key = db.Column(db.String(50), unique=True, nullable=False)
    setting_value = db.Column(db.String(255))
    
    @staticmethod
    def get_logo():
        """Get the current logo filename"""
        setting = AppSettings.query.filter_by(setting_key='logo').first()
        return setting.setting_value if setting else None
    
    @staticmethod
    def set_logo(filename):
        """Set or update the logo filename"""
        setting = AppSettings.query.filter_by(setting_key='logo').first()
        if setting:
            setting.setting_value = filename
        else:
            setting = AppSettings(setting_key='logo', setting_value=filename)
            db.session.add(setting)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_logo():
    """Make app logo available to all templates"""
    return dict(get_app_logo=AppSettings.get_logo)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def validate_severity(severity):
    allowed_severities = ['Low', 'Medium', 'High', 'Critical']
    return severity if severity in allowed_severities else 'Low'


def validate_incident_type(incident_type):
    allowed_types = ['Security', 'Safety']
    return incident_type if incident_type in allowed_types else 'Security'


def get_file_type(filename):
    """Determine if file is image or video based on extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext in ['jpg', 'jpeg', 'bmp']:
        return 'image'
    elif ext in ['mp4', 'avi', 'mov']:
        return 'video'
    return 'other'


def process_file_uploads(files_list, incident):
    """Process multiple file uploads and create IncidentAttachment records"""
    total_size = 0
    max_size = 1024 * 1024 * 1024  # 1GB
    saved_files = []
    
    for file in files_list:
        if file and file.filename and allowed_file(file.filename):
            # Check file size
            file.seek(0, os.SEEK_END)
            file_size = file.tell()
            file.seek(0)  # Reset file pointer
            
            total_size += file_size
            if total_size > max_size:
                # Clean up any already saved files
                for saved_file in saved_files:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], saved_file))
                    except:
                        pass
                raise ValueError(f"Total file size exceeds 1GB limit")
            
            # Save file
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            saved_files.append(filename)
            
            # Create attachment record
            attachment = IncidentAttachment(
                incident_id=incident.id,
                filename=filename,
                file_type=get_file_type(filename),
                file_size=file_size
            )
            db.session.add(attachment)
    
    return len(saved_files)


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        if 'login_attempts' not in session:
            session['login_attempts'] = 0
            session['lockout_until'] = None
        
        if session.get('lockout_until'):
            lockout_time = datetime.fromisoformat(session['lockout_until'])
            if datetime.utcnow() < lockout_time:
                remaining = int((lockout_time - datetime.utcnow()).total_seconds() / 60)
                flash(f'Too many failed login attempts. Please try again in {remaining} minutes.', 'danger')
                return render_template('login.html')
            else:
                session['login_attempts'] = 0
                session['lockout_until'] = None
        
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['login_attempts'] = 0
            session['lockout_until'] = None
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            
            if session['login_attempts'] >= 5:
                session['lockout_until'] = (datetime.utcnow() + timedelta(minutes=15)).isoformat()
                flash('Too many failed login attempts. Account locked for 15 minutes.', 'danger')
            else:
                remaining_attempts = 5 - session['login_attempts']
                flash(f'Invalid username or password. {remaining_attempts} attempts remaining.', 'danger')
    
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    search_query = request.args.get('search', '')
    sort_order = request.args.get('sort', 'asc')  # asc = earliest first (default), desc = latest first
    
    # Build query with sorting
    if sort_order == 'desc':
        incidents = Incident.query.order_by(Incident.incident_datetime.desc())
    else:
        incidents = Incident.query.order_by(Incident.incident_datetime.asc())
    
    # Apply search filter
    if search_query:
        incidents = incidents.filter(
            db.or_(
                Incident.incident_description.contains(search_query),
                Incident.camera_location.contains(search_query),
                Incident.persons_involved.contains(search_query),
                Incident.reported_by.contains(search_query)
            )
        )
    
    incidents = incidents.all()
    return render_template('dashboard.html', incidents=incidents, search_query=search_query, sort_order=sort_order)


@app.route('/incident/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    if request.method == 'POST':
        try:
            incident = Incident(
                incident_type=validate_incident_type(request.form.get('incident_type', 'Security')),
                incident_datetime=datetime.strptime(request.form.get('incident_datetime'), '%Y-%m-%dT%H:%M'),
                camera_location=request.form.get('camera_location'),
                severity=validate_severity(request.form.get('severity', 'Low')),
                incident_description=request.form.get('incident_description'),
                persons_involved=request.form.get('persons_involved'),
                action_taken=request.form.get('action_taken'),
                footage_reference=request.form.get('footage_reference'),
                reported_by=request.form.get('reported_by', current_user.full_name or current_user.username),
                reviewed_by=request.form.get('reviewed_by'),
                remarks_outcome=request.form.get('remarks_outcome')
            )
            
            db.session.add(incident)
            db.session.flush()  # Get incident.id without committing
            
            # Handle multiple file uploads
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                if files:
                    try:
                        files_count = process_file_uploads(files, incident)
                        if files_count > 0:
                            flash(f'{files_count} file(s) uploaded successfully', 'info')
                    except ValueError as e:
                        db.session.rollback()
                        flash(str(e), 'danger')
                        return render_template('incident_form.html', incident=None)
            
            # Add audit log entry in same transaction with description snapshot
            audit = AuditLog(
                incident_id=incident.id,
                action='created',
                user=current_user.username,
                details=f"Incident #{incident.id} created",
                incident_description=incident.incident_description
            )
            db.session.add(audit)
            db.session.commit()  # Single commit for incident, attachments, and audit log
            
            flash('Incident log created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating incident: {str(e)}', 'danger')
            return render_template('incident_form.html', incident=None)
    
    return render_template('incident_form.html', incident=None)


@app.route('/incident/<int:id>')
@login_required
def view_incident(id):
    incident = Incident.query.get_or_404(id)
    return render_template('incident_view.html', incident=incident)


@app.route('/incident/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_incident(id):
    incident = Incident.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            incident.incident_type = validate_incident_type(request.form.get('incident_type', 'Security'))
            incident.incident_datetime = datetime.strptime(request.form.get('incident_datetime'), '%Y-%m-%dT%H:%M')
            incident.camera_location = request.form.get('camera_location')
            incident.severity = validate_severity(request.form.get('severity', 'Low'))
            incident.incident_description = request.form.get('incident_description')
            incident.persons_involved = request.form.get('persons_involved')
            incident.action_taken = request.form.get('action_taken')
            incident.footage_reference = request.form.get('footage_reference')
            incident.reported_by = request.form.get('reported_by')
            incident.reviewed_by = request.form.get('reviewed_by')
            incident.remarks_outcome = request.form.get('remarks_outcome')
            
            # Handle multiple file uploads
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                if files:
                    try:
                        files_count = process_file_uploads(files, incident)
                        if files_count > 0:
                            flash(f'{files_count} new file(s) uploaded successfully', 'info')
                    except ValueError as e:
                        db.session.rollback()
                        flash(str(e), 'danger')
                        return render_template('incident_form.html', incident=incident)
            
            # Add audit log entry in same transaction with description snapshot
            audit = AuditLog(
                incident_id=incident.id,
                action='updated',
                user=current_user.username,
                details=f"Incident #{incident.id} updated",
                incident_description=incident.incident_description
            )
            db.session.add(audit)
            db.session.commit()  # Single commit for incident update, new attachments, and audit log
            
            flash('Incident log updated successfully!', 'success')
            return redirect(url_for('view_incident', id=id))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating incident: {str(e)}', 'danger')
            return render_template('incident_form.html', incident=incident)
    
    return render_template('incident_form.html', incident=incident)


@app.route('/generate-report', methods=['GET', 'POST'])
@login_required
def generate_report():
    """
    Multi-incident report generation with comprehensive filtering.
    
    GET: Display filter form with autocomplete options from existing data
    POST: Process filters and generate print-friendly report for multiple incidents
    
    Note: incidents_report.html is intentionally standalone (doesn't extend base.html)
    to ensure clean PDF output without navigation/UI elements when printing.
    """
    if request.method == 'POST':
        # Get filter parameters from form
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        severity = request.form.get('severity')
        camera_location = request.form.get('camera_location')
        reported_by = request.form.get('reported_by')
        reviewed_by = request.form.get('reviewed_by')
        persons_involved = request.form.get('persons_involved')
        description = request.form.get('description')
        
        # Build query with filters
        query = Incident.query
        
        if start_date:
            start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
            query = query.filter(Incident.incident_datetime >= start_datetime)
        
        if end_date:
            end_datetime = datetime.strptime(end_date, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
            query = query.filter(Incident.incident_datetime <= end_datetime)
        
        if severity and severity != 'All':
            query = query.filter(Incident.severity == severity)
        
        if camera_location:
            query = query.filter(Incident.camera_location.ilike(f'%{camera_location}%'))
        
        if reported_by:
            query = query.filter(Incident.reported_by.ilike(f'%{reported_by}%'))
        
        if reviewed_by:
            query = query.filter(Incident.reviewed_by.ilike(f'%{reviewed_by}%'))
        
        if persons_involved:
            query = query.filter(Incident.persons_involved.ilike(f'%{persons_involved}%'))
        
        if description:
            query = query.filter(Incident.incident_description.ilike(f'%{description}%'))
        
        incidents = query.order_by(Incident.incident_datetime.desc()).all()
        
        return render_template('incidents_report.html', 
                             incidents=incidents, 
                             filters={
                                 'start_date': start_date,
                                 'end_date': end_date,
                                 'severity': severity if severity else 'All',
                                 'camera_location': camera_location,
                                 'reported_by': reported_by,
                                 'reviewed_by': reviewed_by,
                                 'persons_involved': persons_involved,
                                 'description': description
                             },
                             report_date=datetime.now())
    
    # GET request - show filter form
    # Get unique values for filter dropdowns
    locations = db.session.query(Incident.camera_location).distinct().filter(Incident.camera_location.isnot(None)).all()
    locations = [loc[0] for loc in locations if loc[0]]
    
    reporters = db.session.query(Incident.reported_by).distinct().filter(Incident.reported_by.isnot(None)).all()
    reporters = [rep[0] for rep in reporters if rep[0]]
    
    reviewers = db.session.query(Incident.reviewed_by).distinct().filter(Incident.reviewed_by.isnot(None)).all()
    reviewers = [rev[0] for rev in reviewers if rev[0]]
    
    return render_template('report_filter.html', locations=locations, reporters=reporters, reviewers=reviewers)


@app.route('/analytics')
@login_required
def analytics():
    """Analytics dashboard with charts and statistics"""
    from collections import defaultdict
    from datetime import timedelta
    
    # Get all incidents
    incidents = Incident.query.all()
    total_incidents = len(incidents)
    
    # Statistics by incident type
    security_count = sum(1 for i in incidents if i.incident_type == 'Security')
    safety_count = sum(1 for i in incidents if i.incident_type == 'Safety')
    
    # Statistics by severity
    severity_stats = {
        'Low': sum(1 for i in incidents if i.severity == 'Low'),
        'Medium': sum(1 for i in incidents if i.severity == 'Medium'),
        'High': sum(1 for i in incidents if i.severity == 'High'),
        'Critical': sum(1 for i in incidents if i.severity == 'Critical')
    }
    
    # Statistics by review status
    reviewed_count = sum(1 for i in incidents if i.reviewed_by)
    pending_count = total_incidents - reviewed_count
    
    # Incidents by month (last 12 months)
    incidents_by_month = defaultdict(int)
    incidents_by_month_type = defaultdict(lambda: {'Security': 0, 'Safety': 0})
    
    now = datetime.now()
    for i in range(12):
        month_date = now - timedelta(days=30 * i)
        month_key = month_date.strftime('%Y-%m')
        incidents_by_month[month_key] = 0
        incidents_by_month_type[month_key] = {'Security': 0, 'Safety': 0}
    
    for incident in incidents:
        if incident.incident_datetime:
            month_key = incident.incident_datetime.strftime('%Y-%m')
            if month_key in incidents_by_month:
                incidents_by_month[month_key] += 1
                incident_type = incident.incident_type or 'Security'
                incidents_by_month_type[month_key][incident_type] += 1
    
    # Sort months chronologically
    sorted_months = sorted(incidents_by_month.keys())
    month_labels = [datetime.strptime(m, '%Y-%m').strftime('%b %Y') for m in sorted_months]
    month_values = [incidents_by_month[m] for m in sorted_months]
    month_security = [incidents_by_month_type[m]['Security'] for m in sorted_months]
    month_safety = [incidents_by_month_type[m]['Safety'] for m in sorted_months]
    
    # Incidents by camera location (top 10)
    location_stats = defaultdict(int)
    for incident in incidents:
        if incident.camera_location:
            location_stats[incident.camera_location] += 1
    
    top_locations = sorted(location_stats.items(), key=lambda x: x[1], reverse=True)[:10]
    location_labels = [loc[0] for loc in top_locations]
    location_values = [loc[1] for loc in top_locations]
    
    # Incidents by year
    year_stats = defaultdict(int)
    for incident in incidents:
        if incident.incident_datetime:
            year = incident.incident_datetime.year
            year_stats[year] += 1
    
    sorted_years = sorted(year_stats.keys())
    year_labels = [str(y) for y in sorted_years]
    year_values = [year_stats[y] for y in sorted_years]
    
    return render_template('analytics.html',
                         total_incidents=total_incidents,
                         security_count=security_count,
                         safety_count=safety_count,
                         severity_stats=severity_stats,
                         reviewed_count=reviewed_count,
                         pending_count=pending_count,
                         month_labels=month_labels,
                         month_values=month_values,
                         month_security=month_security,
                         month_safety=month_safety,
                         location_labels=location_labels,
                         location_values=location_values,
                         year_labels=year_labels,
                         year_values=year_values)


@app.route('/incident/<int:id>/delete', methods=['POST'])
@login_required
def delete_incident(id):
    incident = Incident.query.get_or_404(id)
    
    # Delete all attachment files first (outside transaction)
    for attachment in incident.attachments:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                flash(f'Warning: Could not delete file {attachment.filename}', 'warning')
    
    # Delete legacy attachment if exists
    if incident.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], incident.attachment_filename)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as e:
                flash(f'Warning: Could not delete legacy attachment', 'warning')
    
    # Add audit log entry and delete incident in single transaction
    # (Attachments will be cascade deleted automatically due to foreign key relationship)
    audit = AuditLog(
        incident_id=incident.id,
        action='deleted',
        user=current_user.username,
        details=f"Incident #{incident.id} deleted",
        incident_description=incident.incident_description
    )
    db.session.add(audit)
    db.session.delete(incident)
    db.session.commit()  # Single commit for both audit log and incident deletion
    flash('Incident log deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/incident/<int:id>/download-files')
@login_required
def download_incident_files(id):
    """Download all incident attachments as a ZIP file"""
    import zipfile
    from io import BytesIO
    
    incident = Incident.query.get_or_404(id)
    
    # Create a BytesIO object to store the ZIP in memory
    memory_file = BytesIO()
    
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add new attachments
        for attachment in incident.attachments:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment.filename)
            if os.path.exists(file_path):
                zf.write(file_path, attachment.filename)
        
        # Add legacy attachment if exists
        if incident.attachment_filename:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], incident.attachment_filename)
            if os.path.exists(file_path):
                zf.write(file_path, incident.attachment_filename)
    
    memory_file.seek(0)
    
    zip_filename = f"incident_{incident.id}_attachments.zip"
    return send_file(memory_file, 
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name=zip_filename)


@app.route('/export/json')
@login_required
def export_json():
    incidents = Incident.query.all()
    data = [incident.to_dict() for incident in incidents]
    
    json_str = json.dumps(data, indent=2)
    buffer = BytesIO()
    buffer.write(json_str.encode('utf-8'))
    buffer.seek(0)
    
    filename = f"incidents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='application/json')


@app.route('/export/csv')
@login_required
def export_csv():
    incidents = Incident.query.all()
    
    output = StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        'ID', 'Incident Type', 'Incident DateTime', 'Camera Location', 'Severity', 'Incident Description',
        'Persons Involved', 'Action Taken', 'Footage Reference', 'Reported By',
        'Reviewed By', 'Remarks/Outcome', 'Attachment Count', 'Attachment Filename', 'Created At', 'Updated At'
    ])
    
    for incident in incidents:
        writer.writerow([
            incident.id,
            incident.incident_type or 'Security',
            incident.incident_datetime.isoformat() if incident.incident_datetime else '',
            incident.camera_location or '',
            incident.severity or 'Low',
            incident.incident_description or '',
            incident.persons_involved or '',
            incident.action_taken or '',
            incident.footage_reference or '',
            incident.reported_by or '',
            incident.reviewed_by or '',
            incident.remarks_outcome or '',
            len(incident.attachments),
            incident.attachment_filename or '',
            incident.created_at.isoformat() if incident.created_at else '',
            incident.updated_at.isoformat() if incident.updated_at else ''
        ])
    
    buffer = BytesIO()
    buffer.write(output.getvalue().encode('utf-8'))
    buffer.seek(0)
    
    filename = f"incidents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype='text/csv')


@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_data():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file uploaded', 'danger')
            return redirect(url_for('import_data'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('import_data'))
        
        try:
            if file.filename.endswith('.json'):
                data = json.load(file)
                imported = 0
                
                for item in data:
                    incident = Incident(
                        incident_type=item.get('incident_type', 'Security'),
                        incident_datetime=datetime.fromisoformat(item['incident_datetime']) if item.get('incident_datetime') else datetime.utcnow(),
                        camera_location=item.get('camera_location'),
                        severity=validate_severity(item.get('severity', 'Low')),
                        incident_description=item.get('incident_description', ''),
                        persons_involved=item.get('persons_involved'),
                        action_taken=item.get('action_taken'),
                        footage_reference=item.get('footage_reference'),
                        reported_by=item.get('reported_by'),
                        reviewed_by=item.get('reviewed_by'),
                        remarks_outcome=item.get('remarks_outcome')
                    )
                    db.session.add(incident)
                    imported += 1
                
                db.session.commit()
                flash(f'Successfully imported {imported} incident(s) from JSON', 'success')
                
            elif file.filename.endswith('.csv'):
                file_content = file.read().decode('utf-8')
                csv_reader = csv.DictReader(StringIO(file_content))
                imported = 0
                
                for row in csv_reader:
                    try:
                        incident = Incident(
                            incident_type=row.get('Incident Type', 'Security'),
                            incident_datetime=datetime.fromisoformat(row['Incident DateTime']) if row.get('Incident DateTime') else datetime.utcnow(),
                            camera_location=row.get('Camera Location'),
                            severity=validate_severity(row.get('Severity', 'Low')),
                            incident_description=row.get('Incident Description', ''),
                            persons_involved=row.get('Persons Involved'),
                            action_taken=row.get('Action Taken'),
                            footage_reference=row.get('Footage Reference'),
                            reported_by=row.get('Reported By'),
                            reviewed_by=row.get('Reviewed By'),
                            remarks_outcome=row.get('Remarks/Outcome')
                        )
                        db.session.add(incident)
                        imported += 1
                    except Exception as e:
                        continue
                
                db.session.commit()
                flash(f'Successfully imported {imported} incident(s) from CSV', 'success')
            else:
                flash('Invalid file format. Please upload JSON or CSV file.', 'danger')
                return redirect(url_for('import_data'))
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            flash(f'Error importing data: {str(e)}', 'danger')
            return redirect(url_for('import_data'))
    
    return render_template('import.html')


@app.route('/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/users/add', methods=['GET', 'POST'])
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        full_name = request.form.get('full_name')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash(f'Username "{username}" already exists. Please choose a different username.', 'danger')
            return render_template('add_user.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('add_user.html')
        
        new_user = User(username=username, full_name=full_name, is_admin=is_admin)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        
        flash(f'User "{username}" created successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('add_user.html')


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('manage_users'))
    
    if user.is_admin:
        flash('Cannot delete admin users. Revoke admin privileges first.', 'danger')
        return redirect(url_for('manage_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{username}" has been deleted.', 'success')
    return redirect(url_for('manage_users'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return render_template('change_password.html')
        
        if len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'danger')
            return render_template('change_password.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return render_template('change_password.html')
        
        current_user.set_password(new_password)
        db.session.commit()
        flash('Your password has been changed successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')


@app.route('/users/<int:user_id>/reset-password', methods=['GET', 'POST'])
@admin_required
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    if user.is_admin:
        flash('Cannot reset password for admin users. Admins must change their own password.', 'danger')
        return redirect(url_for('manage_users'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not new_password or not confirm_password:
            flash('Both password fields are required.', 'danger')
            return render_template('reset_password.html', user=user)
        
        if len(new_password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('reset_password.html', user=user)
        
        if new_password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', user=user)
        
        user.set_password(new_password)
        db.session.commit()
        flash(f'Password for user "{user.username}" has been reset successfully!', 'success')
        return redirect(url_for('manage_users'))
    
    return render_template('reset_password.html', user=user)


@app.route('/audit-history')
@admin_required
def audit_history():
    """Admin-only page to view all incident changes with timestamps and users"""
    page = request.args.get('page', 1, type=int)
    per_page = 50  # Show 50 logs per page
    
    # Get paginated audit logs (no join needed - we have description snapshot)
    pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('audit_history.html', 
                         logs=pagination.items,
                         pagination=pagination)


@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def app_settings():
    """Admin-only page to manage app settings like logo"""
    if request.method == 'POST':
        if 'logo' in request.files:
            file = request.files['logo']
            if file and file.filename:
                # Check if file is an image
                if allowed_file(file.filename):
                    # Remove old logo if exists
                    old_logo = AppSettings.get_logo()
                    if old_logo:
                        old_logo_path = os.path.join(app.config['UPLOAD_FOLDER'], old_logo)
                        if os.path.exists(old_logo_path):
                            os.remove(old_logo_path)
                    
                    # Save new logo
                    filename = secure_filename(file.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"logo_{timestamp}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    
                    # Update settings
                    AppSettings.set_logo(filename)
                    flash('Logo uploaded successfully!', 'success')
                else:
                    flash('Invalid file type. Please upload JPG or BMP files only.', 'danger')
            else:
                flash('No file selected.', 'danger')
        
        # Handle logo removal
        if request.form.get('remove_logo') == 'true':
            old_logo = AppSettings.get_logo()
            if old_logo:
                old_logo_path = os.path.join(app.config['UPLOAD_FOLDER'], old_logo)
                if os.path.exists(old_logo_path):
                    os.remove(old_logo_path)
                AppSettings.set_logo(None)
                flash('Logo removed successfully!', 'success')
        
        return redirect(url_for('app_settings'))
    
    current_logo = AppSettings.get_logo()
    return render_template('settings.html', current_logo=current_logo)


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


def init_db():
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(username='admin').first():
            admin_password = generate_strong_password(20)
            admin = User(username='admin', full_name='Administrator', is_admin=True)
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
            
            print('=' * 80)
            print('IMPORTANT: Default admin user created')
            print('=' * 80)
            print(f'Username: admin')
            print(f'Password: {admin_password}')
            print('=' * 80)
            print('SECURITY WARNING: Save this password now! It will not be shown again.')
            print('Please change this password immediately after first login.')
            print('=' * 80)


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
