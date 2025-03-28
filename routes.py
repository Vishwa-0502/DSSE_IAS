import os
import json
from datetime import datetime
from flask import render_template, redirect, url_for, flash, request, jsonify, send_file, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash

from app import app, db
from models import User, File, FileShare, SearchIndex
from utils.encryption import encrypt_file, decrypt_file, generate_master_key, encrypt_search_index, search_encrypted
from utils.file_handler import process_file, extract_text_from_file, update_file_content
from utils.search import create_search_index, search_file

# Authentication routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_server:
            return redirect(url_for('server_dashboard'))
        else:
            return redirect(url_for('client_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        user_type = request.form.get('user_type')
        
        # Validate form data
        if not username or not email or not password or not confirm_password:
            flash('All fields are required', 'danger')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
            
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists', 'danger')
            return render_template('register.html')
            
        # Check if trying to register as server and if a server already exists
        is_server = user_type == 'server'
        if is_server and User.query.filter_by(is_server=True).first():
            flash('Server account already exists', 'danger')
            return render_template('register.html')
            
        # Create new user
        new_user = User(username=username, email=email, is_server=is_server)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Server routes
@app.route('/server/dashboard')
@login_required
def server_dashboard():
    if not current_user.is_server:
        flash('Access denied: Server privileges required', 'danger')
        return redirect(url_for('index'))
    
    files = File.query.filter_by(uploader_id=current_user.id).all()
    clients = User.query.filter_by(is_server=False).all()
    
    return render_template('server/dashboard.html', files=files, clients=clients)

@app.route('/server/upload', methods=['GET', 'POST'])
@login_required
def server_upload():
    if not current_user.is_server:
        flash('Access denied: Server privileges required', 'danger')
        return redirect(url_for('index'))
    
    clients = User.query.filter_by(is_server=False).all()
    
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        if file:
            filename = secure_filename(file.filename)
            file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'text'
            
            # Generate a master key for encryption
            master_key = generate_master_key()
            
            # Save the original file temporarily
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
            file.save(original_path)
            
            # Process file to extract text
            text_content = extract_text_from_file(original_path, file_type)
            
            # Create encrypted file
            encrypted_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}.enc"
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
            
            # Encrypt the file
            iv, tag, salt = encrypt_file(original_path, encrypted_path, master_key)
            
            # Create search index
            index_data = create_search_index(text_content, master_key)
            
            # Store file information in database
            new_file = File(
                filename=encrypted_filename,
                original_filename=filename,
                file_type=file_type,
                file_size=os.path.getsize(original_path),
                uploader_id=current_user.id,
                iv=iv,
                tag=tag,
                salt=salt,
                index_data=json.dumps(index_data)
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            # Share with selected clients
            client_ids = request.form.getlist('clients')
            for client_id in client_ids:
                file_share = FileShare(
                    file_id=new_file.id,
                    client_id=int(client_id)
                )
                db.session.add(file_share)
            
            db.session.commit()
            
            # Clean up temporary file
            os.remove(original_path)
            
            flash('File encrypted and shared successfully', 'success')
            return redirect(url_for('server_dashboard'))
    
    return render_template('server/upload.html', clients=clients)

@app.route('/server/search', methods=['GET', 'POST'])
@login_required
def server_search():
    if not current_user.is_server:
        flash('Access denied: Server privileges required', 'danger')
        return redirect(url_for('index'))
    
    results = []
    
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        file_id = request.form.get('file_id')
        
        if not keyword:
            flash('Search keyword is required', 'danger')
            return redirect(request.url)
        
        if file_id:
            # Search in specific file
            file = File.query.get(file_id)
            if not file or file.uploader_id != current_user.id:
                flash('File not found or access denied', 'danger')
                return redirect(request.url)
                
            # Perform encrypted search
            search_results = search_encrypted(file, keyword)
            if search_results:
                results.append({
                    'file': file,
                    'matches': search_results
                })
        else:
            # Search in all files uploaded by the server
            files = File.query.filter_by(uploader_id=current_user.id).all()
            for file in files:
                search_results = search_encrypted(file, keyword)
                if search_results:
                    results.append({
                        'file': file,
                        'matches': search_results
                    })
    
    files = File.query.filter_by(uploader_id=current_user.id).all()
    return render_template('server/search.html', files=files, results=results)

@app.route('/server/update/<int:file_id>', methods=['GET', 'POST'])
@login_required
def server_update(file_id):
    if not current_user.is_server:
        flash('Access denied: Server privileges required', 'danger')
        return redirect(url_for('index'))
    
    file = File.query.get_or_404(file_id)
    
    if file.uploader_id != current_user.id:
        flash('Access denied: You can only update your own files', 'danger')
        return redirect(url_for('server_dashboard'))
    
    if request.method == 'POST':
        update_type = request.form.get('update_type')
        
        if update_type == 'file':
            if 'file' not in request.files:
                flash('No file part', 'danger')
                return redirect(request.url)
                
            new_file = request.files['file']
            
            if new_file.filename == '':
                flash('No file selected', 'danger')
                return redirect(request.url)
                
            # Save the new file temporarily
            temp_filename = secure_filename(new_file.filename)
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_update_' + temp_filename)
            new_file.save(temp_path)
            
            # Extract text from new file
            new_text = extract_text_from_file(temp_path, file.file_type)
            
            # Update the file content without decryption
            update_file_content(file, new_text)
            
            # Clean up temporary file
            os.remove(temp_path)
            
        elif update_type == 'text':
            new_text = request.form.get('text_content')
            if not new_text:
                flash('Text content is required', 'danger')
                return redirect(request.url)
                
            # Update the file content without decryption
            update_file_content(file, new_text)
            
        else:
            flash('Invalid update type', 'danger')
            return redirect(request.url)
            
        flash('File updated successfully', 'success')
        return redirect(url_for('server_dashboard'))
    
    return render_template('server/update.html', file=file)

# Client routes
@app.route('/client/dashboard')
@login_required
def client_dashboard():
    if current_user.is_server:
        flash('Access denied: Client view not available for server', 'danger')
        return redirect(url_for('index'))
    
    # Get files shared with the client
    shared_files = FileShare.query.filter_by(client_id=current_user.id, is_active=True).all()
    
    return render_template('client/dashboard.html', shared_files=shared_files)

@app.route('/client/files')
@login_required
def client_files():
    if current_user.is_server:
        flash('Access denied: Client view not available for server', 'danger')
        return redirect(url_for('index'))
    
    # Get files shared with the client
    shared_files = FileShare.query.filter_by(client_id=current_user.id, is_active=True).all()
    
    return render_template('client/files.html', shared_files=shared_files)

@app.route('/client/decrypt/<int:file_id>')
@login_required
def client_decrypt(file_id):
    if current_user.is_server:
        flash('Access denied: Client view not available for server', 'danger')
        return redirect(url_for('index'))
    
    # Check if file is shared with the client
    file_share = FileShare.query.filter_by(file_id=file_id, client_id=current_user.id, is_active=True).first()
    
    if not file_share:
        flash('Access denied: File not shared with you', 'danger')
        return redirect(url_for('client_files'))
    
    file = File.query.get_or_404(file_id)
    
    # Create temporary filename for decrypted file
    decrypted_filename = f"decrypted_{file.original_filename}"
    decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
    
    # Get encrypted file path
    encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    
    # Prompt user for master key (in a real system, this would be securely shared)
    # For demo purposes, we'll use a hardcoded key or retrieve it from a secure source
    master_key = generate_master_key()  # In a real system, this would be securely obtained
    
    # Decrypt the file
    try:
        decrypt_file(encrypted_path, decrypted_path, master_key, file.iv, file.tag, file.salt)
        
        # Return the decrypted file as a download
        return send_file(decrypted_path, as_attachment=True, download_name=file.original_filename)
    except Exception as e:
        flash(f'Decryption failed: {str(e)}', 'danger')
        return redirect(url_for('client_files'))
    finally:
        # Clean up temporary decrypted file
        if os.path.exists(decrypted_path):
            os.remove(decrypted_path)

@app.route('/client/search', methods=['GET', 'POST'])
@login_required
def client_search():
    if current_user.is_server:
        flash('Access denied: Client view not available for server', 'danger')
        return redirect(url_for('index'))
    
    # Get files shared with the client
    shared_files = FileShare.query.filter_by(client_id=current_user.id, is_active=True).all()
    
    results = []
    
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        file_id = request.form.get('file_id')
        
        if not keyword:
            flash('Search keyword is required', 'danger')
            return redirect(request.url)
        
        # For client search, we need to first decrypt the files
        master_key = generate_master_key()  # In a real system, this would be securely obtained
        
        if file_id:
            # Search in specific file
            file_share = FileShare.query.filter_by(file_id=file_id, client_id=current_user.id, is_active=True).first()
            
            if not file_share:
                flash('File not found or access denied', 'danger')
                return redirect(request.url)
                
            file = file_share.file
            
            # Get encrypted file path
            encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            
            # Create temporary filename for decrypted file
            decrypted_filename = f"temp_search_{file.original_filename}"
            decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
            
            try:
                # Decrypt the file
                decrypt_file(encrypted_path, decrypted_path, master_key, file.iv, file.tag, file.salt)
                
                # Search in decrypted file
                search_results = search_file(decrypted_path, keyword)
                
                if search_results:
                    results.append({
                        'file': file,
                        'matches': search_results
                    })
                    
            except Exception as e:
                flash(f'Search failed: {str(e)}', 'danger')
            finally:
                # Clean up temporary decrypted file
                if os.path.exists(decrypted_path):
                    os.remove(decrypted_path)
                    
        else:
            # Search in all shared files
            for file_share in shared_files:
                file = file_share.file
                
                # Get encrypted file path
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                
                # Create temporary filename for decrypted file
                decrypted_filename = f"temp_search_{file.original_filename}"
                decrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)
                
                try:
                    # Decrypt the file
                    decrypt_file(encrypted_path, decrypted_path, master_key, file.iv, file.tag, file.salt)
                    
                    # Search in decrypted file
                    search_results = search_file(decrypted_path, keyword)
                    
                    if search_results:
                        results.append({
                            'file': file,
                            'matches': search_results
                        })
                        
                except Exception as e:
                    flash(f'Search failed for {file.original_filename}: {str(e)}', 'danger')
                finally:
                    # Clean up temporary decrypted file
                    if os.path.exists(decrypted_path):
                        os.remove(decrypted_path)
    
    return render_template('client/search.html', shared_files=shared_files, results=results)
