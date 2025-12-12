import os
import json
import csv
import secrets
import string
import sqlite3
import shutil
import tarfile
import hashlib
import tempfile
import threading
import base64
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import smbclient

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


class BackupConfig(db.Model):
    """Stores backup configuration settings"""
    id = db.Column(db.Integer, primary_key=True)
    shared_folder_path = db.Column(db.String(500))
    backup_enabled = db.Column(db.Boolean, default=False)
    schedule_frequency = db.Column(db.String(20), default='daily')  # daily, weekly, monthly
    schedule_time = db.Column(db.String(5), default='02:00')  # HH:MM format
    retention_count = db.Column(db.Integer, default=30)  # Keep last N backups
    last_backup_time = db.Column(db.DateTime)
    last_backup_status = db.Column(db.String(20))  # success, failed
    
    use_smb = db.Column(db.Boolean, default=False)
    smb_server = db.Column(db.String(255))
    smb_share = db.Column(db.String(255))
    smb_port = db.Column(db.Integer, default=445)
    smb_domain = db.Column(db.String(255))
    smb_username = db.Column(db.String(255))  # Optional: store in DB instead of env
    smb_password_encrypted = db.Column(db.Text)  # Encrypted password
    
    @staticmethod
    def get_config():
        """Get or create backup configuration"""
        config = BackupConfig.query.first()
        if not config:
            config = BackupConfig()
            db.session.add(config)
            db.session.commit()
        return config


class BackupJob(db.Model):
    """Tracks individual backup/restore operations"""
    id = db.Column(db.Integer, primary_key=True)
    job_type = db.Column(db.String(20), nullable=False)  # backup, restore
    status = db.Column(db.String(20), nullable=False)  # running, success, failed
    started_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime)
    user = db.Column(db.String(80))  # User who triggered (or 'system' for scheduled)
    backup_path = db.Column(db.String(500))
    incident_count = db.Column(db.Integer)
    file_count = db.Column(db.Integer)
    total_size_mb = db.Column(db.Float)
    error_message = db.Column(db.Text)
    job_metadata = db.Column(db.Text)  # JSON string with additional details


class IncidentType(db.Model):
    """Stores custom incident types (e.g., Security, Safety, Fire, Medical)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    color = db.Column(db.String(20), default='primary')  # Bootstrap color: primary, success, warning, danger, info, secondary
    icon = db.Column(db.String(10), default='')  # Optional emoji icon
    is_active = db.Column(db.Boolean, default=True)
    display_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def get_all_active():
        """Get all active incident types ordered by display_order"""
        return IncidentType.query.filter_by(is_active=True).order_by(IncidentType.display_order, IncidentType.name).all()
    
    @staticmethod
    def get_all():
        """Get all incident types including inactive"""
        return IncidentType.query.order_by(IncidentType.display_order, IncidentType.name).all()
    
    @staticmethod
    def seed_defaults():
        """Create default incident types if they don't exist"""
        defaults = [
            {'name': 'Security', 'color': 'primary', 'icon': '', 'display_order': 1},
            {'name': 'Safety', 'color': 'warning', 'icon': '', 'display_order': 2}
        ]
        for item in defaults:
            if not IncidentType.query.filter_by(name=item['name']).first():
                incident_type = IncidentType(**item)
                db.session.add(incident_type)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.context_processor
def inject_logo():
    """Make app logo available to all templates"""
    return dict(get_app_logo=AppSettings.get_logo)


@app.context_processor
def inject_incident_types():
    """Make incident types available to all templates"""
    return dict(get_incident_types=get_incident_types, get_incident_type_info=get_incident_type_info)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


def validate_severity(severity):
    allowed_severities = ['Low', 'Medium', 'High', 'Critical']
    return severity if severity in allowed_severities else 'Low'


def validate_incident_type(incident_type, allow_inactive=False):
    """Validate incident type against database of allowed types.
    
    Args:
        incident_type: The type name to validate
        allow_inactive: If True, allow inactive types (for editing existing incidents)
    """
    try:
        if allow_inactive:
            all_types = [t.name for t in IncidentType.get_all()]
            if incident_type in all_types:
                return incident_type
        allowed_types = [t.name for t in IncidentType.get_all_active()]
        if not allowed_types:
            allowed_types = ['Security', 'Safety']
        return incident_type if incident_type in allowed_types else allowed_types[0]
    except Exception:
        return incident_type if incident_type in ['Security', 'Safety'] else 'Security'


def get_incident_types(include_type=None):
    """Get all active incident types for dropdowns.
    
    Args:
        include_type: Optional type name to include even if inactive (for editing existing incidents)
    """
    try:
        types = list(IncidentType.get_all_active())
        if include_type and include_type not in [t.name for t in types]:
            inactive_type = IncidentType.query.filter_by(name=include_type).first()
            if inactive_type:
                types.append(inactive_type)
        if types:
            return types
        return [type('obj', (object,), {'name': 'Security', 'color': 'primary', 'icon': ''})(),
                type('obj', (object,), {'name': 'Safety', 'color': 'warning', 'icon': ''})()]
    except Exception:
        return [type('obj', (object,), {'name': 'Security', 'color': 'primary', 'icon': ''})(),
                type('obj', (object,), {'name': 'Safety', 'color': 'warning', 'icon': ''})()]


def get_incident_type_info(type_name):
    """Get incident type info by name for badge display"""
    try:
        itype = IncidentType.query.filter_by(name=type_name).first()
        if itype:
            return {'name': itype.name, 'color': itype.color, 'icon': itype.icon}
    except Exception:
        pass
    defaults = {
        'Security': {'name': 'Security', 'color': 'primary', 'icon': ''},
        'Safety': {'name': 'Safety', 'color': 'warning', 'icon': ''}
    }
    return defaults.get(type_name, {'name': type_name, 'color': 'secondary', 'icon': ''})


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


def calculate_sha256(filepath):
    """Calculate SHA256 checksum of a file"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_encryption_key():
    """Derive encryption key from SESSION_SECRET for symmetric encryption of SMB credentials"""
    # Use SESSION_SECRET to derive a stable encryption key
    # WARNING: This is for LAN-only low-risk environments as explicitly requested by user
    session_secret = app.config['SECRET_KEY'].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'incident_log_smb_salt',  # Fixed salt for consistent key derivation
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(session_secret))
    return key


def encrypt_password(password):
    """Encrypt SMB password for database storage (LAN low-risk environment only)"""
    if not password:
        return None
    try:
        f = Fernet(get_encryption_key())
        return f.encrypt(password.encode()).decode()
    except Exception as e:
        app.logger.error(f"SMB password encryption failed: {e}")
        raise ValueError(f"Failed to encrypt SMB password: {str(e)}")


def decrypt_password(encrypted_password):
    """Decrypt SMB password from database"""
    if not encrypted_password:
        return None
    try:
        f = Fernet(get_encryption_key())
        return f.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        app.logger.error(f"SMB password decryption failed (possibly corrupted or SESSION_SECRET changed): {e}")
        raise ValueError(f"Failed to decrypt SMB password - credentials may be corrupted")


def get_smb_credentials():
    """
    Get SMB credentials from database first, then fallback to environment secrets.
    Priority: Database credentials > Environment variables
    NOTE: Database storage is for LAN-only low-risk environments as requested by user
    Returns: (username, password, source) tuple where source is 'database' or 'environment'
    """
    try:
        config = BackupConfig.get_config()
        
        # Check database first
        if config.smb_username and config.smb_password_encrypted:
            try:
                password = decrypt_password(config.smb_password_encrypted)
                if password:
                    app.logger.info("Using SMB credentials from database")
                    return config.smb_username, password, 'database'
            except ValueError as e:
                app.logger.error(f"Database SMB credentials failed decryption: {e}. Falling back to environment variables.")
    except Exception as e:
        app.logger.error(f"Error reading SMB credentials from database: {e}. Falling back to environment variables.")
    
    # Fallback to environment variables
    username = os.environ.get('SMB_USERNAME')
    password = os.environ.get('SMB_PASSWORD')
    if username and password:
        app.logger.info("Using SMB credentials from environment variables")
    return username, password, 'environment'


def get_smb_path(config, path=''):
    """Construct SMB UNC path from config"""
    if not config.use_smb or not config.smb_server or not config.smb_share:
        return None
    return rf'\\{config.smb_server}\{config.smb_share}\{path}'.replace('/', '\\')


def test_smb_connection(config):
    """Test SMB connection with current settings"""
    try:
        username, password, _ = get_smb_credentials()
        if not username or not password:
            return False, "SMB credentials not configured. Please set SMB_USERNAME and SMB_PASSWORD in environment secrets or database."
        
        if not config.smb_server or not config.smb_share:
            return False, "SMB server and share must be configured."
        
        smbclient.register_session(
            config.smb_server,
            username=username,
            password=password,
            port=config.smb_port or 445
        )
        
        smb_path = get_smb_path(config, '')
        try:
            smbclient.listdir(smb_path)
            return True, "SMB connection successful!"
        except Exception as e:
            return False, f"Cannot access SMB share: {str(e)}"
            
    except Exception as e:
        return False, f"SMB connection failed: {str(e)}"


def smb_makedirs(path):
    """Create directories on SMB share (similar to os.makedirs)"""
    try:
        parts = path.strip('\\').split('\\')
        current_path = f'\\\\{parts[0]}\\{parts[1]}'
        
        for part in parts[2:]:
            current_path = os.path.join(current_path, part).replace('/', '\\')
            try:
                smbclient.mkdir(current_path)
            except Exception:
                pass
        return True
    except Exception as e:
        raise Exception(f"Failed to create SMB directories: {str(e)}")


def smb_copy_file(src_local, dst_smb):
    """Copy a local file to SMB share"""
    try:
        with open(src_local, 'rb') as src:
            with smbclient.open_file(dst_smb, mode='wb') as dst:
                shutil.copyfileobj(src, dst)
    except Exception as e:
        raise Exception(f"Failed to copy file to SMB: {str(e)}")


def smb_copy_from_smb(src_smb, dst_local):
    """Copy a file from SMB share to local"""
    try:
        with smbclient.open_file(src_smb, mode='rb') as src:
            with open(dst_local, 'wb') as dst:
                shutil.copyfileobj(src, dst)
    except Exception as e:
        raise Exception(f"Failed to copy file from SMB: {str(e)}")


def create_backup(user='system'):
    """Create a complete backup of database and media files"""
    if not backup_lock.acquire(blocking=False):
        return False, "Another backup operation is currently in progress. Please wait."
    
    job = None
    
    try:
        try:
            job = BackupJob(job_type='backup', status='running', user=user)
            db.session.add(job)
            db.session.commit()
        except Exception as e:
            return False, f"Failed to create backup job: {str(e)}"
        config = BackupConfig.get_config()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        year_month_path = datetime.now().strftime('%Y/%m')
        
        if config.use_smb:
            username, password, _ = get_smb_credentials()
            if not username or not password:
                raise ValueError("SMB credentials not configured. Please set credentials in database or environment variables.")
            
            if not config.smb_server or not config.smb_share:
                raise ValueError("SMB server and share must be configured")
            
            smbclient.register_session(
                config.smb_server,
                username=username,
                password=password,
                port=config.smb_port or 445
            )
            
            backup_path_rel = f'incident_backups\\{year_month_path}\\{timestamp}'
            backup_dir = get_smb_path(config, backup_path_rel)
            smb_makedirs(backup_dir)
        else:
            if not config.shared_folder_path:
                raise ValueError("Shared folder path not configured")
            
            if not os.path.exists(config.shared_folder_path):
                raise ValueError(f"Shared folder path does not exist: {config.shared_folder_path}")
            
            if not os.access(config.shared_folder_path, os.W_OK):
                raise ValueError(f"No write permission to shared folder: {config.shared_folder_path}")
            
            backup_dir = os.path.join(config.shared_folder_path, 'incident_backups', year_month_path, timestamp)
            os.makedirs(backup_dir, exist_ok=True)
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            db_temp_path = os.path.join(temp_dir, 'incidents.db')
            source_db = sqlite3.connect(DB_PATH)
            dest_db = sqlite3.connect(db_temp_path)
            with dest_db:
                source_db.backup(dest_db)
            source_db.close()
            dest_db.close()
            
            backup_contents = os.path.join(temp_dir, 'backup_data')
            os.makedirs(backup_contents, exist_ok=True)
            shutil.copy2(db_temp_path, os.path.join(backup_contents, 'incidents.db'))
            
            uploads_dest = os.path.join(backup_contents, 'uploads')
            if os.path.exists(app.config['UPLOAD_FOLDER']) and os.listdir(app.config['UPLOAD_FOLDER']):
                shutil.copytree(app.config['UPLOAD_FOLDER'], uploads_dest)
            else:
                os.makedirs(uploads_dest, exist_ok=True)
            
            temp_archive_path = os.path.join(temp_dir, 'backup.tar.gz')
            with tarfile.open(temp_archive_path, 'w:gz') as tar:
                tar.add(backup_contents, arcname='.')
            
            db_checksum = calculate_sha256(os.path.join(backup_contents, 'incidents.db'))
            archive_checksum = calculate_sha256(temp_archive_path)
            
            incident_count = Incident.query.count()
            
            file_count = 0
            uploads_size = 0
            if os.path.exists(uploads_dest):
                for root, dirs, files in os.walk(uploads_dest):
                    file_count += len(files)
                    for file in files:
                        uploads_size += os.path.getsize(os.path.join(root, file))
            
            archive_size = os.path.getsize(temp_archive_path)
            total_size_mb = archive_size / (1024 * 1024)
            
            metadata = {
                'version': '1.0',
                'timestamp': timestamp,
                'backup_type': 'full',
                'incident_count': incident_count,
                'media_file_count': file_count,
                'database_checksum': db_checksum,
                'archive_checksum': archive_checksum,
                'archive_size_bytes': archive_size,
                'media_size_bytes': uploads_size,
                'created_by': user
            }
            
            temp_metadata_path = os.path.join(temp_dir, 'metadata.json')
            with open(temp_metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            if config.use_smb:
                archive_dest = os.path.join(backup_dir, 'backup.tar.gz').replace('/', '\\')
                metadata_dest = os.path.join(backup_dir, 'metadata.json').replace('/', '\\')
                smb_copy_file(temp_archive_path, archive_dest)
                smb_copy_file(temp_metadata_path, metadata_dest)
            else:
                shutil.copy2(temp_archive_path, os.path.join(backup_dir, 'backup.tar.gz'))
                shutil.copy2(temp_metadata_path, os.path.join(backup_dir, 'metadata.json'))
            
            job.status = 'success'
            job.completed_at = datetime.utcnow()
            job.backup_path = backup_dir
            job.incident_count = incident_count
            job.file_count = file_count
            job.total_size_mb = total_size_mb
            job.job_metadata = json.dumps(metadata)
            
            config.last_backup_time = datetime.utcnow()
            config.last_backup_status = 'success'
            
            db.session.commit()
            
            cleanup_old_backups(config)
            
            return True, f"Backup created successfully at {backup_dir}"
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        try:
            if job:
                job.status = 'failed'
                job.completed_at = datetime.utcnow()
                job.error_message = str(e)
                
            config = BackupConfig.get_config()
            config.last_backup_status = 'failed'
            
            db.session.commit()
        except:
            pass
        
        return False, f"Backup failed: {str(e)}"
    finally:
        backup_lock.release()


def cleanup_old_backups(config):
    """Remove old backups based on retention policy"""
    try:
        backups_root = os.path.join(config.shared_folder_path, 'incident_backups')
        if not os.path.exists(backups_root):
            return
        
        backup_list = []
        for year_dir in os.listdir(backups_root):
            year_path = os.path.join(backups_root, year_dir)
            if not os.path.isdir(year_path):
                continue
            for month_dir in os.listdir(year_path):
                month_path = os.path.join(year_path, month_dir)
                if not os.path.isdir(month_path):
                    continue
                for backup_dir in os.listdir(month_path):
                    backup_path = os.path.join(month_path, backup_dir)
                    if os.path.isdir(backup_path):
                        metadata_path = os.path.join(backup_path, 'metadata.json')
                        if os.path.exists(metadata_path):
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                backup_list.append({
                                    'path': backup_path,
                                    'timestamp': metadata.get('timestamp', ''),
                                    'created_at': datetime.strptime(metadata.get('timestamp', '19700101_000000'), '%Y%m%d_%H%M%S')
                                })
        
        backup_list.sort(key=lambda x: x['created_at'], reverse=True)
        
        if len(backup_list) > config.retention_count:
            for backup in backup_list[config.retention_count:]:
                shutil.rmtree(backup['path'], ignore_errors=True)
                
    except Exception as e:
        print(f"Error cleaning up old backups: {e}")


def restore_from_backup(backup_path, user='admin'):
    """Restore database and media files from a backup"""
    if not backup_lock.acquire(blocking=False):
        return False, "Another backup/restore operation is currently in progress. Please wait."
    
    job = None
    
    try:
        try:
            config = BackupConfig.get_config()
            
            # Validate configuration based on backup mode
            if config.use_smb:
                # For SMB mode, validate SMB configuration
                if not config.smb_server or not config.smb_share:
                    return False, "SMB server and share not configured"
                
                # Validate that backup_path is within the SMB share
                smb_base_path = f"\\\\{config.smb_server}\\{config.smb_share}"
                if not backup_path.startswith(smb_base_path):
                    return False, "Security Error: Backup path is outside configured SMB share"
            else:
                # For local mode, validate local path
                if not config.shared_folder_path:
                    return False, "Shared folder path not configured"
                
                backup_path_normalized = os.path.normpath(os.path.abspath(backup_path))
                shared_folder_normalized = os.path.normpath(os.path.abspath(config.shared_folder_path))
                
                try:
                    common_path = os.path.commonpath([backup_path_normalized, shared_folder_normalized])
                    if common_path != shared_folder_normalized:
                        return False, "Security Error: Backup path is outside configured shared folder"
                except ValueError:
                    return False, "Security Error: Backup path is outside configured shared folder"
            
            job = BackupJob(job_type='restore', status='running', user=user)
            db.session.add(job)
            db.session.commit()
        except Exception as e:
            if isinstance(e, ValueError) and "Security Error" in str(e):
                raise
            return False, f"Failed to create restore job: {str(e)}"
        # Read metadata and archive files (from SMB if configured)
        temp_restore_dir = None  # Track temp directory for cleanup
        
        if config.use_smb:
            # For SMB, backup_path is like \\server\share\incident_backups\2025\11\20251122_123456
            # Download metadata.json and backup.tar.gz from SMB to temp location
            temp_restore_dir = tempfile.mkdtemp(prefix='restore_')
            metadata_path = os.path.join(temp_restore_dir, 'metadata.json')
            archive_path = os.path.join(temp_restore_dir, 'backup.tar.gz')
            
            try:
                username, password, _ = get_smb_credentials()
                if not username or not password:
                    raise ValueError("SMB credentials not configured. Please set credentials in database or environment variables.")
                
                smbclient.register_session(
                    config.smb_server,
                    username=username,
                    password=password,
                    port=config.smb_port or 445
                )
                
                # Construct SMB paths
                smb_base_path = f"\\\\{config.smb_server}\\{config.smb_share}"
                # Extract the relative path from backup_path
                # backup_path format: \\server\share\incident_backups\2025\11\20251122_123456
                parts = backup_path.replace(smb_base_path, '').strip('\\').split('\\')
                smb_metadata_path = smb_base_path + '\\' + '\\'.join(parts) + '\\metadata.json'
                smb_archive_path = smb_base_path + '\\' + '\\'.join(parts) + '\\backup.tar.gz'
                
                # Download files from SMB
                with smbclient.open_file(smb_metadata_path, mode='rb') as smb_file:
                    with open(metadata_path, 'wb') as local_file:
                        local_file.write(smb_file.read())
                
                with smbclient.open_file(smb_archive_path, mode='rb') as smb_file:
                    with open(archive_path, 'wb') as local_file:
                        local_file.write(smb_file.read())
                
            except Exception as e:
                shutil.rmtree(temp_restore_dir, ignore_errors=True)
                raise ValueError(f"Failed to read backup from SMB share: {str(e)}")
        else:
            # Local filesystem mode
            metadata_path = os.path.join(backup_path, 'metadata.json')
            if not os.path.exists(metadata_path):
                raise ValueError("Invalid backup: metadata.json not found")
            
            archive_path = os.path.join(backup_path, 'backup.tar.gz')
            if not os.path.exists(archive_path):
                raise ValueError("Invalid backup: backup.tar.gz not found")
        
        # Read metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Verify archive integrity
        archive_checksum = calculate_sha256(archive_path)
        if archive_checksum != metadata.get('archive_checksum'):
            raise ValueError("Backup integrity check failed: checksum mismatch")
        
        pre_restore_backup, msg = create_backup(user=f'{user}_pre_restore')
        if not pre_restore_backup:
            raise ValueError(f"Failed to create pre-restore backup: {msg}")
        
        temp_dir = tempfile.mkdtemp()
        
        try:
            with tarfile.open(archive_path, 'r:gz') as tar:
                tar.extractall(temp_dir)
            
            restored_db = os.path.join(temp_dir, 'incidents.db')
            if not os.path.exists(restored_db):
                raise ValueError("Invalid backup: incidents.db not found in archive")
            
            db_checksum = calculate_sha256(restored_db)
            if db_checksum != metadata.get('database_checksum'):
                raise ValueError("Database integrity check failed: checksum mismatch")
            
            if os.path.exists(app.config['UPLOAD_FOLDER']):
                shutil.rmtree(app.config['UPLOAD_FOLDER'])
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            
            restored_uploads = os.path.join(temp_dir, 'uploads')
            if os.path.exists(restored_uploads):
                for item in os.listdir(restored_uploads):
                    src = os.path.join(restored_uploads, item)
                    dst = os.path.join(app.config['UPLOAD_FOLDER'], item)
                    if os.path.isdir(src):
                        shutil.copytree(src, dst)
                    else:
                        shutil.copy2(src, dst)
            
            shutil.copy2(restored_db, DB_PATH)
            
            job.status = 'success'
            job.completed_at = datetime.utcnow()
            job.backup_path = backup_path
            job.incident_count = metadata.get('incident_count')
            job.file_count = metadata.get('media_file_count')
            job.total_size_mb = metadata.get('archive_size_bytes', 0) / (1024 * 1024)
            job.job_metadata = json.dumps(metadata)
            
            db.session.commit()
            
            return True, f"Successfully restored from backup: {metadata.get('timestamp')}"
            
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
            # Clean up temp restore directory if it was created for SMB restore
            if temp_restore_dir:
                shutil.rmtree(temp_restore_dir, ignore_errors=True)
            
    except Exception as e:
        try:
            if job:
                job.status = 'failed'
                job.completed_at = datetime.utcnow()
                job.error_message = str(e)
                db.session.commit()
        except:
            pass
        
        return False, f"Restore failed: {str(e)}"
    finally:
        backup_lock.release()


def get_available_backups(config):
    """List all available backups from the shared folder or SMB share"""
    backups = []
    
    try:
        if config.use_smb:
            username, password, _ = get_smb_credentials()
            if not username or not password or not config.smb_server or not config.smb_share:
                return backups
            
            smbclient.register_session(
                config.smb_server,
                username=username,
                password=password,
                port=config.smb_port or 445
            )
            
            backups_root = get_smb_path(config, 'incident_backups')
            
            try:
                year_dirs = smbclient.listdir(backups_root)
            except Exception:
                return backups
            
            for year_dir in year_dirs:
                if year_dir in ['.', '..']:
                    continue
                year_path = os.path.join(backups_root, year_dir).replace('/', '\\')
                try:
                    month_dirs = smbclient.listdir(year_path)
                except Exception:
                    continue
                for month_dir in month_dirs:
                    if month_dir in ['.', '..']:
                        continue
                    month_path = os.path.join(year_path, month_dir).replace('/', '\\')
                    try:
                        backup_dirs = smbclient.listdir(month_path)
                    except Exception:
                        continue
                    for backup_dir in backup_dirs:
                        if backup_dir in ['.', '..']:
                            continue
                        backup_path = os.path.join(month_path, backup_dir).replace('/', '\\')
                        metadata_path = os.path.join(backup_path, 'metadata.json').replace('/', '\\')
                        try:
                            with smbclient.open_file(metadata_path, mode='r') as f:
                                metadata = json.load(f)
                                backups.append({
                                    'path': backup_path,
                                    'metadata': metadata
                                })
                        except Exception:
                            continue
        else:
            shared_folder_path = config.shared_folder_path
            backups_root = os.path.join(shared_folder_path, 'incident_backups')
            if not os.path.exists(backups_root):
                return backups
            
            for year_dir in os.listdir(backups_root):
                year_path = os.path.join(backups_root, year_dir)
                if not os.path.isdir(year_path):
                    continue
                for month_dir in os.listdir(year_path):
                    month_path = os.path.join(year_path, month_dir)
                    if not os.path.isdir(month_path):
                        continue
                    for backup_dir in os.listdir(month_path):
                        backup_path = os.path.join(month_path, backup_dir)
                        if os.path.isdir(backup_path):
                            metadata_path = os.path.join(backup_path, 'metadata.json')
                            if os.path.exists(metadata_path):
                                with open(metadata_path, 'r') as f:
                                    metadata = json.load(f)
                                    backups.append({
                                        'path': backup_path,
                                        'metadata': metadata
                                    })
        
        backups.sort(key=lambda x: x['metadata'].get('timestamp', ''), reverse=True)
        
    except Exception as e:
        print(f"Error listing backups: {e}")
    
    return backups


scheduler = BackgroundScheduler()
backup_lock = threading.RLock()


def scheduled_backup():
    """Function to be called by the scheduler"""
    with app.app_context():
        config = BackupConfig.get_config()
        if config.backup_enabled and config.shared_folder_path:
            create_backup(user='system')


def update_backup_schedule():
    """Update the backup schedule based on current configuration"""
    try:
        with app.app_context():
            scheduler.remove_all_jobs()
            
            config = BackupConfig.get_config()
            
            if config.backup_enabled and config.shared_folder_path:
                hour, minute = map(int, config.schedule_time.split(':'))
                
                if config.schedule_frequency == 'daily':
                    scheduler.add_job(
                        func=scheduled_backup,
                        trigger=CronTrigger(hour=hour, minute=minute),
                        id='backup_job',
                        name='Daily Backup',
                        replace_existing=True
                    )
                elif config.schedule_frequency == 'weekly':
                    scheduler.add_job(
                        func=scheduled_backup,
                        trigger=CronTrigger(day_of_week=0, hour=hour, minute=minute),
                        id='backup_job',
                        name='Weekly Backup',
                        replace_existing=True
                    )
                elif config.schedule_frequency == 'monthly':
                    scheduler.add_job(
                        func=scheduled_backup,
                        trigger=CronTrigger(day=1, hour=hour, minute=minute),
                        id='backup_job',
                        name='Monthly Backup',
                        replace_existing=True
                    )
                    
    except Exception as e:
        print(f"Error updating backup schedule: {e}")


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
            incident.incident_type = validate_incident_type(request.form.get('incident_type', 'Security'), allow_inactive=True)
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
        incident_type = request.form.get('incident_type')
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
        
        if incident_type and incident_type != 'All':
            query = query.filter(Incident.incident_type == incident_type)
        
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
                                 'incident_type': incident_type if incident_type else 'All',
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


@app.route('/incident-types')
@admin_required
def incident_types():
    """Admin-only page to manage incident types"""
    types = IncidentType.get_all()
    return render_template('incident_types.html', incident_types=types)


@app.route('/incident-types/add', methods=['GET', 'POST'])
@admin_required
def add_incident_type():
    """Add a new incident type"""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'primary')
        icon = request.form.get('icon', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        
        if not name:
            flash('Incident type name is required.', 'danger')
            return render_template('incident_type_form.html', incident_type=None, colors=get_bootstrap_colors())
        
        if IncidentType.query.filter_by(name=name).first():
            flash(f'Incident type "{name}" already exists.', 'danger')
            return render_template('incident_type_form.html', incident_type=None, colors=get_bootstrap_colors())
        
        new_type = IncidentType(
            name=name,
            color=color,
            icon=icon,
            display_order=display_order
        )
        db.session.add(new_type)
        db.session.commit()
        
        flash(f'Incident type "{name}" created successfully!', 'success')
        return redirect(url_for('incident_types'))
    
    return render_template('incident_type_form.html', incident_type=None, colors=get_bootstrap_colors())


@app.route('/incident-types/edit/<int:type_id>', methods=['GET', 'POST'])
@admin_required
def edit_incident_type(type_id):
    """Edit an existing incident type"""
    incident_type = IncidentType.query.get_or_404(type_id)
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        color = request.form.get('color', 'primary')
        icon = request.form.get('icon', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        is_active = request.form.get('is_active') == 'on'
        
        if not name:
            flash('Incident type name is required.', 'danger')
            return render_template('incident_type_form.html', incident_type=incident_type, colors=get_bootstrap_colors())
        
        existing = IncidentType.query.filter_by(name=name).first()
        if existing and existing.id != type_id:
            flash(f'Incident type "{name}" already exists.', 'danger')
            return render_template('incident_type_form.html', incident_type=incident_type, colors=get_bootstrap_colors())
        
        incident_type.name = name
        incident_type.color = color
        incident_type.icon = icon
        incident_type.display_order = display_order
        incident_type.is_active = is_active
        db.session.commit()
        
        flash(f'Incident type "{name}" updated successfully!', 'success')
        return redirect(url_for('incident_types'))
    
    return render_template('incident_type_form.html', incident_type=incident_type, colors=get_bootstrap_colors())


@app.route('/incident-types/delete/<int:type_id>', methods=['POST'])
@admin_required
def delete_incident_type(type_id):
    """Delete an incident type (only if not in use)"""
    incident_type = IncidentType.query.get_or_404(type_id)
    
    in_use_count = Incident.query.filter_by(incident_type=incident_type.name).count()
    if in_use_count > 0:
        flash(f'Cannot delete "{incident_type.name}" - it is used by {in_use_count} incident(s). Deactivate it instead.', 'danger')
        return redirect(url_for('incident_types'))
    
    name = incident_type.name
    db.session.delete(incident_type)
    db.session.commit()
    
    flash(f'Incident type "{name}" deleted successfully!', 'success')
    return redirect(url_for('incident_types'))


def get_bootstrap_colors():
    """Return available Bootstrap color options"""
    return [
        {'value': 'primary', 'name': 'Blue (Primary)', 'class': 'bg-primary'},
        {'value': 'secondary', 'name': 'Gray (Secondary)', 'class': 'bg-secondary'},
        {'value': 'success', 'name': 'Green (Success)', 'class': 'bg-success'},
        {'value': 'danger', 'name': 'Red (Danger)', 'class': 'bg-danger'},
        {'value': 'warning', 'name': 'Yellow (Warning)', 'class': 'bg-warning'},
        {'value': 'info', 'name': 'Cyan (Info)', 'class': 'bg-info'},
        {'value': 'dark', 'name': 'Dark', 'class': 'bg-dark'},
    ]


@app.route('/backup-settings', methods=['GET', 'POST'])
@admin_required
def backup_settings():
    """Admin-only page to configure backup settings"""
    config = BackupConfig.get_config()
    
    if request.method == 'POST':
        config.use_smb = request.form.get('use_smb') == 'on'
        config.smb_server = request.form.get('smb_server', '').strip()
        config.smb_share = request.form.get('smb_share', '').strip()
        config.smb_port = int(request.form.get('smb_port', 445))
        config.smb_domain = request.form.get('smb_domain', '').strip()
        config.shared_folder_path = request.form.get('shared_folder_path', '').strip()
        config.backup_enabled = request.form.get('backup_enabled') == 'on'
        config.schedule_frequency = request.form.get('schedule_frequency', 'daily')
        config.schedule_time = request.form.get('schedule_time', '02:00')
        config.retention_count = int(request.form.get('retention_count', 30))
        
        # Handle SMB credentials (optional: database storage for LAN low-risk environment)
        smb_username = request.form.get('smb_username', '').strip()
        smb_password = request.form.get('smb_password', '').strip()
        
        try:
            if smb_username and smb_password:
                # User provided credentials - store in database with encryption
                config.smb_username = smb_username
                config.smb_password_encrypted = encrypt_password(smb_password)
            elif smb_username == '' and smb_password == '':
                # User cleared credentials - remove from database
                config.smb_username = None
                config.smb_password_encrypted = None
        except ValueError as e:
            flash(f'Error encrypting SMB credentials: {str(e)}', 'danger')
            return render_template('backup_settings.html', config=config)
        
        if config.use_smb:
            if not config.smb_server or not config.smb_share:
                flash('Error: SMB server and share must be configured when using SMB', 'danger')
            else:
                username, password, source = get_smb_credentials()
                if not username or not password:
                    flash('Warning: No SMB credentials configured. Please provide credentials in the form or set SMB_USERNAME and SMB_PASSWORD environment variables.', 'warning')
                db.session.commit()
                update_backup_schedule()
                flash(f'Backup settings saved successfully! SMB mode enabled (credentials from {source}).', 'success')
                return redirect(url_for('backup_settings'))
        elif config.shared_folder_path:
            if not os.path.exists(config.shared_folder_path):
                flash(f'Error: Shared folder path does not exist: {config.shared_folder_path}', 'danger')
            elif not os.access(config.shared_folder_path, os.W_OK):
                flash(f'Error: No write permission to shared folder: {config.shared_folder_path}', 'danger')
            else:
                db.session.commit()
                update_backup_schedule()
                flash('Backup settings saved successfully!', 'success')
                return redirect(url_for('backup_settings'))
        else:
            db.session.commit()
            update_backup_schedule()
            flash('Backup settings saved (no backup path configured)', 'success')
            return redirect(url_for('backup_settings'))
    
    return render_template('backup_settings.html', config=config)


@app.route('/test-smb-connection', methods=['POST'])
@admin_required
def test_smb_connection_route():
    """Test SMB connection with provided settings"""
    smb_server = request.form.get('smb_server', '').strip()
    smb_share = request.form.get('smb_share', '').strip()
    smb_port = int(request.form.get('smb_port', 445))
    smb_username = request.form.get('smb_username', '').strip()
    smb_password = request.form.get('smb_password', '').strip()
    
    if not smb_server or not smb_share:
        return jsonify({'success': False, 'message': 'SMB server and share are required'}), 400
    
    # Use credentials from form if provided, otherwise get from storage
    if smb_username and smb_password:
        username = smb_username
        password = smb_password
    else:
        username, password, source = get_smb_credentials()
        if not username or not password:
            return jsonify({'success': False, 'message': 'SMB credentials not configured. Please provide credentials in the form or set SMB_USERNAME and SMB_PASSWORD in environment secrets.'}), 400
    
    # Test the connection with provided credentials
    try:
        # Clear any cached sessions to ensure we test with fresh credentials
        try:
            smbclient.reset_connection_cache()
        except:
            pass  # Ignore if cache doesn't exist
        
        # Register new session with provided credentials
        smbclient.register_session(
            smb_server,
            username=username,
            password=password,
            port=smb_port
        )
        
        # Attempt to list the share to validate authentication and access
        smb_path = f"\\\\{smb_server}\\{smb_share}"
        try:
            smbclient.listdir(smb_path)
            return jsonify({'success': True, 'message': 'SMB connection and authentication successful!'})
        except Exception as e:
            return jsonify({'success': False, 'message': f'Cannot access SMB share: {str(e)}'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'SMB authentication failed: {str(e)}'})


@app.route('/backup-now', methods=['POST'])
@admin_required
def backup_now():
    """Manually trigger a backup"""
    config = BackupConfig.get_config()
    
    # Validate configuration based on mode
    if config.use_smb:
        if not config.smb_server or not config.smb_share:
            flash('Error: SMB server and share not configured. Please configure backup settings first.', 'danger')
            return redirect(url_for('backup_management'))
        username, password, _ = get_smb_credentials()
        if not username or not password:
            flash('Error: SMB credentials not configured. Please provide credentials in backup settings.', 'danger')
            return redirect(url_for('backup_management'))
    else:
        if not config.shared_folder_path:
            flash('Error: Shared folder path not configured. Please configure backup settings first.', 'danger')
            return redirect(url_for('backup_management'))
        
        if not os.path.exists(config.shared_folder_path):
            flash(f'Error: Shared folder does not exist: {config.shared_folder_path}', 'danger')
            return redirect(url_for('backup_management'))
        
        if not os.access(config.shared_folder_path, os.W_OK):
            flash(f'Error: No write permission to shared folder: {config.shared_folder_path}', 'danger')
            return redirect(url_for('backup_management'))
    
    success, message = create_backup(user=current_user.username)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'danger')
    return redirect(url_for('backup_management'))


@app.route('/backup-management')
@admin_required
def backup_management():
    """Admin-only page to view backup history and available backups"""
    config = BackupConfig.get_config()
    
    jobs = BackupJob.query.order_by(BackupJob.started_at.desc()).limit(50).all()
    
    available_backups = []
    if config.shared_folder_path:
        # For SMB, always try to get backups; for local, check existence first
        if config.use_smb or os.path.exists(config.shared_folder_path):
            available_backups = get_available_backups(config)
    
    return render_template('backup_management.html', 
                         config=config, 
                         jobs=jobs,
                         backups=available_backups)


@app.route('/restore-backup', methods=['POST'])
@admin_required
def restore_backup_route():
    """Restore from a selected backup"""
    backup_path = request.form.get('backup_path')
    
    if not backup_path:
        flash('Invalid backup path selected', 'danger')
        return redirect(url_for('backup_management'))
    
    config = BackupConfig.get_config()
    
    # Configuration validation depends on backup mode
    if config.use_smb:
        if not config.smb_server or not config.smb_share:
            flash('SMB server and share not configured', 'danger')
            return redirect(url_for('backup_management'))
    else:
        if not config.shared_folder_path:
            flash('Shared folder path not configured', 'danger')
            return redirect(url_for('backup_management'))
    
    # Path validation: skip filesystem checks for SMB paths
    if config.use_smb:
        # For SMB, just validate that backup_path starts with the expected SMB base path
        smb_base_path = f"\\\\{config.smb_server}\\{config.smb_share}"
        if not backup_path.startswith(smb_base_path):
            flash('Security Error: Backup path is outside configured SMB share', 'danger')
            return redirect(url_for('backup_management'))
    else:
        # For local filesystem, check if path exists and is within shared folder
        if not os.path.exists(backup_path):
            flash('Invalid backup path selected', 'danger')
            return redirect(url_for('backup_management'))
        
        backup_path_normalized = os.path.normpath(os.path.abspath(backup_path))
        shared_folder_normalized = os.path.normpath(os.path.abspath(config.shared_folder_path))
        
        if not backup_path_normalized.startswith(shared_folder_normalized):
            flash('Security Error: Backup path is outside configured shared folder', 'danger')
            return redirect(url_for('backup_management'))
    
    success, message = restore_from_backup(backup_path, user=current_user.username)
    
    if success:
        flash(f'{message}. The application will reload to reflect the restored data.', 'warning')
        flash('IMPORTANT: The database and files have been restored. Please verify your data.', 'info')
    else:
        flash(message, 'danger')
    
    return redirect(url_for('backup_management'))


def generate_strong_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


def init_db():
    with app.app_context():
        db.create_all()
        
        IncidentType.seed_defaults()
        
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
    scheduler.start()
    update_backup_schedule()
    app.run(host='0.0.0.0', port=5000, debug=True)
