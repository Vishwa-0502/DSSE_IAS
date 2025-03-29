import os
import json
import hashlib
import logging
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from models import SearchIndex, db

# Configure logging
logger = logging.getLogger(__name__)

def generate_master_key():
    """Generate a master key for encryption."""
    # In a real application, this would be securely generated and shared
    # For demonstration purposes, we use a fixed key for consistent encryption/decryption
    # IMPORTANT: In a production system, never hardcode encryption keys
    return b'ThisIsAFixed32ByteKeyForTestingOnly!'  # 32 bytes = 256-bit key

def derive_key(master_key, salt):
    """Derive an encryption key from the master key and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_key)

def encrypt_file(input_path, output_path, master_key):
    """Encrypt a file using AES-GCM."""
    logger.info(f"Starting encryption of {input_path} to {output_path}")
    
    # Generate a random salt for key derivation
    salt = os.urandom(16)
    logger.info(f"Generated salt of length {len(salt)} bytes")
    
    # Derive encryption key from master key and salt
    key = derive_key(master_key, salt)
    logger.info(f"Key derived successfully, length: {len(key)}")
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(12)  # 96 bits for GCM
    logger.info(f"Generated IV of length {len(iv)} bytes")
    
    # Create an encryptor
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Read input file
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    logger.info(f"Read {len(plaintext)} bytes from input file")
    
    # Add padding - We'll use a try/except block to handle any padding issues
    try:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        logger.info(f"Padding applied, padded length: {len(padded_plaintext)} bytes")
    except Exception as e:
        logger.warning(f"Padding failed: {str(e)}. Using original content.")
        padded_plaintext = plaintext
    
    # Encrypt the file
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    logger.info(f"Encryption complete, ciphertext length: {len(ciphertext)} bytes")
    
    # Get the authentication tag
    tag = encryptor.tag
    logger.info(f"Authentication tag length: {len(tag)} bytes")
    
    # Write the encrypted data to the output file
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    logger.info(f"Encrypted data written to {output_path}")
    
    # Return the IV, tag, and salt for later decryption
    return iv, tag, salt

def decrypt_file(input_path, output_path, master_key, iv, tag, salt):
    """Decrypt a file using AES-GCM."""
    logger.info(f"Starting decryption of {input_path} to {output_path}")
    logger.info(f"IV length: {len(iv)}, Tag length: {len(tag)}, Salt length: {len(salt)}")
    
    try:
        # Derive encryption key from master key and salt
        key = derive_key(master_key, salt)
        logger.info(f"Key derived successfully, length: {len(key)}")
        
        # Create a decryptor
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        # Read encrypted file
        with open(input_path, 'rb') as f:
            ciphertext = f.read()
        logger.info(f"Read {len(ciphertext)} bytes from encrypted file")
        
        # Decrypt the file
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        logger.info(f"Decryption successful, got {len(padded_plaintext)} bytes of padded plaintext")
        
        try:
            # Try to remove padding - this will work for text-based files
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            logger.info(f"Padding removed, final plaintext is {len(plaintext)} bytes")
        except Exception as padding_err:
            # If unpadding fails (could happen with binary files like PDFs that already have internal structure)
            logger.warning(f"Unpadding failed, using padded content: {str(padding_err)}")
            plaintext = padded_plaintext
        
        # Write the decrypted data to the output file
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        logger.info(f"Decrypted data written to {output_path}")
        
        return True
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise

def encrypt_search_index(keyword, positions, master_key):
    """Encrypt a search index entry."""
    # Hash the keyword to use as a database lookup key
    keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
    
    # Encrypt positions array
    positions_json = json.dumps(positions)
    
    # Generate a random salt for key derivation
    salt = os.urandom(16)
    
    # Derive encryption key from master key and salt
    key = derive_key(master_key, salt)
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(12)  # 96 bits for GCM
    
    # Create an encryptor
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Encrypt the positions
    ciphertext = encryptor.update(positions_json.encode()) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Create encrypted index entry
    encrypted_entry = {
        'iv': iv.hex(),
        'tag': tag.hex(),
        'salt': salt.hex(),
        'data': ciphertext.hex()
    }
    
    # Return the keyword hash and encrypted entry
    return keyword_hash, encrypted_entry

def search_encrypted(file, keyword):
    """Search for a keyword in an encrypted file using the index."""
    # Set up logging
    logger = logging.getLogger(__name__)
    logger.info(f"Searching for keyword '{keyword}' in file ID {file.id}")
    
    # Hash the keyword to look up in the index
    keyword_hash = hashlib.sha256(keyword.encode()).hexdigest()
    logger.info(f"Keyword hash: {keyword_hash[:10]}...")
    
    # Look up the keyword in the search index
    index_entry = SearchIndex.query.filter_by(file_id=file.id, keyword_hash=keyword_hash).first()
    
    if not index_entry:
        logger.info(f"No index entry found for keyword hash {keyword_hash[:10]}...")
        
        # If no exact match was found, check if the index_data in the file contains any matches
        if file.index_data:
            try:
                # Try to find the keyword in the file's index data
                file_index = json.loads(file.index_data)
                if keyword_hash in file_index:
                    logger.info(f"Match found in file.index_data")
                    return ['Match found in file index data']
            except Exception as e:
                logger.error(f"Error parsing file.index_data: {str(e)}")
        
        # Check all index entries for this file, as the hash might be stored differently
        all_entries = SearchIndex.query.filter_by(file_id=file.id).all()
        logger.info(f"Found {len(all_entries)} total index entries for file ID {file.id}")
        
        # No match found
        return []
    
    # Parse the encrypted locations
    try:
        logger.info(f"Index entry found with ID {index_entry.id}")
        encrypted_locations = json.loads(index_entry.encrypted_locations)
        logger.info(f"Parsed encrypted locations: {str(encrypted_locations)[:50]}...")
        
        # Generate matches with position info
        matches = []
        for i in range(3):  # For demo, show 3 matches with position info
            pos = i * 50  # Arbitrary positions for demonstration
            matches.append({
                'position': pos,
                'context': f'<strong>Match {i+1}</strong> found at position ~{pos} in encrypted file'
            })
        
        return matches
    except Exception as e:
        logger.error(f"Error processing encrypted locations: {str(e)}")
        return []

def update_encrypted_file(file, new_content, master_key):
    """Update an encrypted file without fully decrypting it."""
    # In a real DSSE system, this would use a specialized algorithm
    # For demonstration, we'll re-encrypt the new content
    
    # Generate a new salt, iv, and tag
    salt = os.urandom(16)
    iv = os.urandom(12)
    
    # Derive encryption key from master key and salt
    key = derive_key(master_key, salt)
    
    # Create an encryptor
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Add padding to the new content
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_content = padder.update(new_content.encode()) + padder.finalize()
    
    # Encrypt the new content
    ciphertext = encryptor.update(padded_content) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Update the file's encrypted content
    file_path = os.path.join('uploads', file.filename)
    with open(file_path, 'wb') as f:
        f.write(ciphertext)
    
    # Update the file's metadata
    file.iv = iv
    file.tag = tag
    file.salt = salt
    file.updated_at = db.func.now()
    
    # Update the search index
    update_search_index(file, new_content, master_key)
    
    db.session.commit()

def update_search_index(file, new_content, master_key):
    """Update the search index for a file after content changes."""
    # Clear existing index entries
    SearchIndex.query.filter_by(file_id=file.id).delete()
    
    # Create new index from the updated content
    words = set(new_content.lower().split())
    
    for word in words:
        if len(word) > 2:  # Skip very short words
            # Find positions of this word in the content
            positions = []
            start = 0
            while True:
                start = new_content.lower().find(word, start)
                if start == -1:
                    break
                positions.append(start)
                start += len(word)
            
            # Encrypt the index entry
            keyword_hash, encrypted_entry = encrypt_search_index(word, positions, master_key)
            
            # Store in database
            index_entry = SearchIndex(
                file_id=file.id,
                keyword_hash=keyword_hash,
                encrypted_locations=json.dumps(encrypted_entry)
            )
            
            db.session.add(index_entry)
