from app.extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

class User(UserMixin, db.Model):
    __tablename__ = 'web_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True)
    is_admin = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanJob(db.Model):
    __tablename__ = 'web_scan_jobs'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(20), nullable=False)  # subnet, range, target, local
    scan_type = db.Column(db.String(20), nullable=False)  # basic, full
    workers = db.Column(db.Integer, default=50)
    username = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))
    find_foxit = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')  # pending, running, completed, failed
    created_by = db.Column(db.Integer, db.ForeignKey('web_users.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    session_id = db.Column(db.Integer)  # Database session ID if job is successful
    progress = db.Column(db.Float, default=0.0)  # Percentage complete
    total_hosts = db.Column(db.Integer, default=0)
    hosts_scanned = db.Column(db.Integer, default=0)
    hosts_online = db.Column(db.Integer, default=0)
    log_output = db.Column(db.Text)
    
    user = db.relationship('User', backref=db.backref('scan_jobs', lazy='dynamic'))
    
    def set_password(self, password):
        if password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None
    
    def get_progress_data(self):
        return {
            'id': self.id,
            'status': self.status,
            'progress': self.progress,
            'hosts_scanned': self.hosts_scanned,
            'hosts_online': self.hosts_online,
            'total_hosts': self.total_hosts,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
    
    def __repr__(self):
        return f'<ScanJob {self.name}>'

class SavedQuery(db.Model):
    __tablename__ = 'web_saved_queries'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    query_type = db.Column(db.String(20), nullable=False)  # predefined, custom
    query_key = db.Column(db.String(50))  # For predefined queries
    sql_query = db.Column(db.Text)  # For custom SQL queries
    parameters = db.Column(db.Text)  # JSON string of parameters
    created_by = db.Column(db.Integer, db.ForeignKey('web_users.id'))
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_run = db.Column(db.DateTime)
    
    user = db.relationship('User', backref=db.backref('saved_queries', lazy='dynamic'))
    
    def get_parameters(self):
        if self.parameters:
            return json.loads(self.parameters)
        return {}
    
    def set_parameters(self, params_dict):
        self.parameters = json.dumps(params_dict)
    
    def __repr__(self):
        return f'<SavedQuery {self.name}>'
