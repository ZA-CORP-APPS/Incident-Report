import os
import json
import csv
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import StringIO, BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'incidents.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'bmp'}

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
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    incident_datetime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    camera_location = db.Column(db.String(200))
    incident_description = db.Column(db.Text, nullable=False)
    persons_involved = db.Column(db.Text)
    action_taken = db.Column(db.Text)
    footage_reference = db.Column(db.String(200))
    reported_by = db.Column(db.String(120))
    reviewed_by = db.Column(db.String(120))
    remarks_outcome = db.Column(db.Text)
    attachment_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'incident_datetime': self.incident_datetime.isoformat() if self.incident_datetime else None,
            'camera_location': self.camera_location,
            'incident_description': self.incident_description,
            'persons_involved': self.persons_involved,
            'action_taken': self.action_taken,
            'footage_reference': self.footage_reference,
            'reported_by': self.reported_by,
            'reviewed_by': self.reviewed_by,
            'remarks_outcome': self.remarks_outcome,
            'attachment_filename': self.attachment_filename,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


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
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
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
    incidents = Incident.query.order_by(Incident.incident_datetime.desc())
    
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
    return render_template('dashboard.html', incidents=incidents, search_query=search_query)


@app.route('/incident/new', methods=['GET', 'POST'])
@login_required
def new_incident():
    if request.method == 'POST':
        incident = Incident(
            incident_datetime=datetime.strptime(request.form.get('incident_datetime'), '%Y-%m-%dT%H:%M'),
            camera_location=request.form.get('camera_location'),
            incident_description=request.form.get('incident_description'),
            persons_involved=request.form.get('persons_involved'),
            action_taken=request.form.get('action_taken'),
            footage_reference=request.form.get('footage_reference'),
            reported_by=request.form.get('reported_by', current_user.full_name or current_user.username),
            reviewed_by=request.form.get('reviewed_by'),
            remarks_outcome=request.form.get('remarks_outcome')
        )
        
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                incident.attachment_filename = filename
        
        db.session.add(incident)
        db.session.commit()
        flash('Incident log created successfully!', 'success')
        return redirect(url_for('dashboard'))
    
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
        incident.incident_datetime = datetime.strptime(request.form.get('incident_datetime'), '%Y-%m-%dT%H:%M')
        incident.camera_location = request.form.get('camera_location')
        incident.incident_description = request.form.get('incident_description')
        incident.persons_involved = request.form.get('persons_involved')
        incident.action_taken = request.form.get('action_taken')
        incident.footage_reference = request.form.get('footage_reference')
        incident.reported_by = request.form.get('reported_by')
        incident.reviewed_by = request.form.get('reviewed_by')
        incident.remarks_outcome = request.form.get('remarks_outcome')
        
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename and allowed_file(file.filename):
                if incident.attachment_filename:
                    old_file = os.path.join(app.config['UPLOAD_FOLDER'], incident.attachment_filename)
                    if os.path.exists(old_file):
                        os.remove(old_file)
                
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                incident.attachment_filename = filename
        
        db.session.commit()
        flash('Incident log updated successfully!', 'success')
        return redirect(url_for('view_incident', id=id))
    
    return render_template('incident_form.html', incident=incident)


@app.route('/incident/<int:id>/delete', methods=['POST'])
@login_required
def delete_incident(id):
    incident = Incident.query.get_or_404(id)
    
    if incident.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], incident.attachment_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(incident)
    db.session.commit()
    flash('Incident log deleted successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


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
        'ID', 'Incident DateTime', 'Camera Location', 'Incident Description',
        'Persons Involved', 'Action Taken', 'Footage Reference', 'Reported By',
        'Reviewed By', 'Remarks/Outcome', 'Attachment Filename', 'Created At', 'Updated At'
    ])
    
    for incident in incidents:
        writer.writerow([
            incident.id,
            incident.incident_datetime.isoformat() if incident.incident_datetime else '',
            incident.camera_location or '',
            incident.incident_description or '',
            incident.persons_involved or '',
            incident.action_taken or '',
            incident.footage_reference or '',
            incident.reported_by or '',
            incident.reviewed_by or '',
            incident.remarks_outcome or '',
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
                        incident_datetime=datetime.fromisoformat(item['incident_datetime']) if item.get('incident_datetime') else datetime.utcnow(),
                        camera_location=item.get('camera_location'),
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
                            incident_datetime=datetime.fromisoformat(row['Incident DateTime']) if row.get('Incident DateTime') else datetime.utcnow(),
                            camera_location=row.get('Camera Location'),
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


def init_db():
    with app.app_context():
        db.create_all()
        
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', full_name='Administrator')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print('Default admin user created (username: admin, password: admin123)')


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
