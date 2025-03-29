import os
import io
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
    import logging
    logger = logging.getLogger(__name__)
    
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
            try:
                filename = secure_filename(file.filename)
                file_type = filename.rsplit('.', 1)[1].lower() if '.' in filename else 'text'
                logger.info(f"Processing file upload: {filename}, type: {file_type}")
                
                # Generate a master key for encryption
                master_key = generate_master_key()
                logger.info(f"Generated master key: length {len(master_key)}")
                
                # Save the original file temporarily
                original_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_' + filename)
                file.save(original_path)
                file_size = os.path.getsize(original_path)
                logger.info(f"Saved original file to {original_path}, size: {file_size} bytes")
                
                # Process file to extract text
                text_content = extract_text_from_file(original_path, file_type)
                logger.info(f"Extracted text content, length: {len(text_content)} chars")
                
                # Create encrypted file
                encrypted_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}.enc"
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
                
                # Encrypt the file
                iv, tag, salt = encrypt_file(original_path, encrypted_path, master_key)
                logger.info(f"File encrypted. IV type: {type(iv)}, IV length: {len(iv)}")
                logger.info(f"Tag type: {type(tag)}, Tag length: {len(tag)}")
                logger.info(f"Salt type: {type(salt)}, Salt length: {len(salt)}")
                
                # Ensure iv, tag, and salt are binary data (bytes)
                if not isinstance(iv, bytes):
                    logger.warning(f"IV is not bytes, converting from {type(iv)}")
                    iv = bytes(iv)
                
                if not isinstance(tag, bytes):
                    logger.warning(f"Tag is not bytes, converting from {type(tag)}")
                    tag = bytes(tag)
                
                if not isinstance(salt, bytes):
                    logger.warning(f"Salt is not bytes, converting from {type(salt)}")
                    salt = bytes(salt)
                
                logger.info(f"After conversion - IV: {len(iv)} bytes, Tag: {len(tag)} bytes, Salt: {len(salt)} bytes")
                
                # Create a new file record first so we have an ID
                new_file = File(
                    filename=encrypted_filename,
                    original_filename=filename,
                    file_type=file_type,
                    file_size=file_size,
                    uploader_id=current_user.id,
                    iv=iv,
                    tag=tag,
                    salt=salt
                )
                
                # Add the file to the database to get an ID
                db.session.add(new_file)
                db.session.flush()
                logger.info(f"Created file database record with ID: {new_file.id}")
                
                # Create search index with the file_id
                index_data = create_search_index(text_content, master_key, new_file.id)
                logger.info(f"Created search index with {len(index_data) if index_data else 0} entries")
                
                # Log the keyword hashes for debugging
                logger.info(f"Index contains keywords with hashes: {list(index_data.keys())[:5]}")
                
                # Update the file with the index data
                new_file.index_data = json.dumps(index_data)
                
                # Commit changes to ensure the search index entries are saved
                db.session.flush()
                
                db.session.add(new_file)
                db.session.commit()
                
                # Share with selected clients
                client_ids = request.form.getlist('clients')
                logger.info(f"Sharing file with {len(client_ids)} clients")
                
                for client_id in client_ids:
                    file_share = FileShare(
                        file_id=new_file.id,
                        client_id=int(client_id)
                    )
                    db.session.add(file_share)
                
                db.session.commit()
                logger.info("File shares created and committed to database")
                
                # Clean up temporary file
                os.remove(original_path)
                logger.info("Removed temporary original file")
                
                flash('File encrypted and shared successfully', 'success')
                return redirect(url_for('server_dashboard'))
            except Exception as e:
                logger.error(f"File upload failed: {str(e)}", exc_info=True)
                db.session.rollback()
                flash(f'File upload failed: {str(e)}', 'danger')
                return redirect(request.url)
    
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
    import logging
    import io
    import tempfile
    import shutil
    logger = logging.getLogger(__name__)
    
    if current_user.is_server:
        flash('Access denied: Client view not available for server', 'danger')
        return redirect(url_for('index'))
    
    # Check if file is shared with the client
    file_share = FileShare.query.filter_by(file_id=file_id, client_id=current_user.id, is_active=True).first()
    
    if not file_share:
        flash('Access denied: File not shared with you', 'danger')
        return redirect(url_for('client_files'))
    
    file = File.query.get_or_404(file_id)
    
    # Use a safer approach with tempfile module for better cleanup
    temp_dir = tempfile.mkdtemp(dir=app.config['UPLOAD_FOLDER'])
    try:
        logger.info(f"Created temporary directory: {temp_dir}")
        
        # Create paths
        decrypted_filename = f"decrypted_{file.original_filename}"
        decrypted_path = os.path.join(temp_dir, decrypted_filename)
        encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        
        # Log file metadata
        logger.info(f"File ID: {file.id}, Original name: {file.original_filename}, Type: {file.file_type}")
        logger.info(f"IV type: {type(file.iv)}, IV length: {len(file.iv) if file.iv else 0}")
        logger.info(f"Tag type: {type(file.tag)}, Tag length: {len(file.tag) if file.tag else 0}")
        logger.info(f"Salt type: {type(file.salt)}, Salt length: {len(file.salt) if file.salt else 0}")
        
        # Ensure iv, tag, and salt are binary data (bytes)
        if file.iv is None or file.tag is None or file.salt is None:
            logger.error("Missing encryption parameters - IV, tag, or salt is None")
            flash('Error: File missing encryption parameters', 'danger')
            return redirect(url_for('client_files'))
        
        # Ensure encryption parameters are in bytes format
        iv = file.iv if isinstance(file.iv, bytes) else bytes(file.iv)
        tag = file.tag if isinstance(file.tag, bytes) else bytes(file.tag)
        salt = file.salt if isinstance(file.salt, bytes) else bytes(file.salt)
        
        logger.info(f"After conversion - IV: {len(iv)} bytes, Tag: {len(tag)} bytes, Salt: {len(salt)} bytes")
        
        # For demo purposes, we'll use a consistent key
        master_key = generate_master_key()
        logger.info(f"Master key length: {len(master_key)}")
        
        # Check if file exists on disk
        if not os.path.exists(encrypted_path):
            logger.error(f"Encrypted file not found at {encrypted_path}")
            flash('Error: Encrypted file not found on the server', 'danger')
            return redirect(url_for('client_files'))
        
        # Decrypt the file
        try:
            logger.info(f"Starting decryption of file {file_id}")
            decrypt_file(encrypted_path, decrypted_path, master_key, iv, tag, salt)
            logger.info(f"Decryption completed, checking output file")
            
            if not os.path.exists(decrypted_path):
                logger.error(f"Decrypted file not created at {decrypted_path}")
                flash('Error: Failed to create decrypted file', 'danger')
                return redirect(url_for('client_files'))
            
            # Read file data into memory in binary mode
            with open(decrypted_path, 'rb') as f:
                file_data = f.read()
            
            logger.info(f"Successfully read {len(file_data)} bytes from decrypted file")
            
            # Set correct MIME type based on file type
            mime_type = 'application/octet-stream'  # Default
            if file.file_type == 'pdf':
                mime_type = 'application/pdf'
            elif file.file_type in ['txt', 'text']:
                mime_type = 'text/plain'
            elif file.file_type in ['mp3', 'wav', 'ogg']:
                if file.file_type == 'mp3':
                    mime_type = 'audio/mpeg'
                elif file.file_type == 'wav':
                    mime_type = 'audio/wav'
                elif file.file_type == 'ogg':
                    mime_type = 'audio/ogg'
            
            logger.info(f"Using MIME type: {mime_type} for file type: {file.file_type}")
            
            # Create a response with the file data
            response = app.response_class(
                io.BytesIO(file_data),
                mimetype=mime_type,
                direct_passthrough=True
            )
            response.headers.set('Content-Disposition', f'attachment; filename={file.original_filename}')
            response.headers.set('Content-Length', str(len(file_data)))
            logger.info(f"Sending decrypted file to client, size: {len(file_data)} bytes")
            return response
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}", exc_info=True)
            flash(f'Decryption failed: {str(e)}', 'danger')
            return redirect(url_for('client_files'))
            
    finally:
        # Always clean up the temporary directory
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temporary directory: {temp_dir}")
        except Exception as cleanup_err:
            logger.error(f"Failed to clean up temporary directory: {str(cleanup_err)}")
            # Continue even if cleanup fails

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
                # Ensure iv, tag, and salt are binary data (bytes)
                iv = file.iv if isinstance(file.iv, bytes) else bytes(file.iv) if file.iv else None
                tag = file.tag if isinstance(file.tag, bytes) else bytes(file.tag) if file.tag else None
                salt = file.salt if isinstance(file.salt, bytes) else bytes(file.salt) if file.salt else None
                
                # Skip decryption if any parameters are missing
                if iv is None or tag is None or salt is None:
                    raise ValueError("Missing encryption parameters")
                
                # Decrypt the file
                decrypt_file(encrypted_path, decrypted_path, master_key, iv, tag, salt)
                
                # Read the file content and close the file immediately
                try:
                    # For binary files like PDFs, try to read in binary mode first
                    if file.file_type == 'pdf':
                        with open(decrypted_path, 'rb') as f:
                            file_data = f.read()
                        # Try to extract text from PDF
                        import PyPDF2
                        import io as py_io
                        pdf = PyPDF2.PdfReader(py_io.BytesIO(file_data))
                        file_content = ""
                        for page_num in range(len(pdf.pages)):
                            file_content += pdf.pages[page_num].extract_text() + "\n"
                    else:
                        # For text files, read as text
                        with open(decrypted_path, 'r', errors='ignore') as f:
                            file_content = f.read()
                except Exception as read_err:
                    import logging
                    logging.error(f"Error reading file content: {str(read_err)}")
                    # Fallback to binary reading with text conversion
                    with open(decrypted_path, 'rb') as f:
                        file_data = f.read()
                    # Try to convert binary to string
                    try:
                        file_content = file_data.decode('utf-8', errors='ignore')
                    except:
                        file_content = str(file_data)
                
                # Remove the file as soon as we're done with it
                if os.path.exists(decrypted_path):
                    os.remove(decrypted_path)
                
                # Search in the file content
                search_results = search_file(io.StringIO(file_content), keyword)
                
                if search_results:
                    results.append({
                        'file': file,
                        'matches': search_results
                    })
                    
            except Exception as e:
                flash(f'Search failed: {str(e)}', 'danger')
            finally:
                # Just in case, try to clean up again
                try:
                    if os.path.exists(decrypted_path):
                        os.remove(decrypted_path)
                except:
                    pass
                    
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
                    # Ensure iv, tag, and salt are binary data (bytes)
                    iv = file.iv if isinstance(file.iv, bytes) else bytes(file.iv) if file.iv else None
                    tag = file.tag if isinstance(file.tag, bytes) else bytes(file.tag) if file.tag else None
                    salt = file.salt if isinstance(file.salt, bytes) else bytes(file.salt) if file.salt else None
                    
                    # Skip decryption if any parameters are missing
                    if iv is None or tag is None or salt is None:
                        raise ValueError("Missing encryption parameters")
                    
                    # Decrypt the file
                    decrypt_file(encrypted_path, decrypted_path, master_key, iv, tag, salt)
                    
                    # Read the file content and close the file immediately
                    try:
                        # For binary files like PDFs, try to read in binary mode first
                        if file.file_type == 'pdf':
                            with open(decrypted_path, 'rb') as f:
                                file_data = f.read()
                            # Try to extract text from PDF
                            import PyPDF2
                            import io as py_io
                            pdf = PyPDF2.PdfReader(py_io.BytesIO(file_data))
                            file_content = ""
                            for page_num in range(len(pdf.pages)):
                                file_content += pdf.pages[page_num].extract_text() + "\n"
                        else:
                            # For text files, read as text
                            with open(decrypted_path, 'r', errors='ignore') as f:
                                file_content = f.read()
                    except Exception as read_err:
                        import logging
                        logging.error(f"Error reading file content: {str(read_err)}")
                        # Fallback to binary reading with text conversion
                        with open(decrypted_path, 'rb') as f:
                            file_data = f.read()
                        # Try to convert binary to string
                        try:
                            file_content = file_data.decode('utf-8', errors='ignore')
                        except:
                            file_content = str(file_data)
                    
                    # Remove the file as soon as we're done with it
                    if os.path.exists(decrypted_path):
                        os.remove(decrypted_path)
                    
                    # Search in the file content
                    search_results = search_file(io.StringIO(file_content), keyword)
                    
                    if search_results:
                        results.append({
                            'file': file,
                            'matches': search_results
                        })
                        
                except Exception as e:
                    flash(f'Search failed for {file.original_filename}: {str(e)}', 'danger')
                finally:
                    # Just in case, try to clean up again
                    try:
                        if os.path.exists(decrypted_path):
                            os.remove(decrypted_path)
                    except:
                        pass
    
    return render_template('client/search.html', shared_files=shared_files, results=results)
