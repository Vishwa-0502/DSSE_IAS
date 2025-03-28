from datetime import datetime
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_server = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    uploaded_files = db.relationship('File', backref='uploader', lazy='dynamic', 
                                    foreign_keys='File.uploader_id')
    shared_files = db.relationship('FileShare', backref='client', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # pdf, text, voice
    file_size = db.Column(db.Integer, nullable=False)
    encrypted = db.Column(db.Boolean, default=True)
    uploader_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Encryption metadata
    iv = db.Column(db.LargeBinary, nullable=True)  # Initialization vector
    tag = db.Column(db.LargeBinary, nullable=True)  # Authentication tag
    salt = db.Column(db.LargeBinary, nullable=True)  # Salt for key derivation
    
    # Index data for searchable encryption
    index_data = db.Column(db.Text, nullable=True)  # Encrypted index for search
    
    # Relationships
    shares = db.relationship('FileShare', backref='file', lazy='dynamic')
    
    def __repr__(self):
        return f'<File {self.original_filename}>'

class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<FileShare file_id={self.file_id} client_id={self.client_id}>'

class SearchIndex(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    keyword_hash = db.Column(db.String(256), nullable=False)
    encrypted_locations = db.Column(db.Text, nullable=False)  # JSON array of encrypted positions
    
    __table_args__ = (db.UniqueConstraint('file_id', 'keyword_hash', name='_file_keyword_uc'),)
    
    def __repr__(self):
        return f'<SearchIndex file_id={self.file_id} keyword_hash={self.keyword_hash[:10]}...>'
