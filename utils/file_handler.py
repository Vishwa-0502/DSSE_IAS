import os
import io
import PyPDF2
import speech_recognition as sr
from models import SearchIndex, db
from utils.encryption import update_encrypted_file
from utils.search import create_search_index

def process_file(file_path, file_type):
    """Process uploaded file based on its type."""
    if file_type == 'txt' or file_type == 'text':
        return process_text_file(file_path)
    elif file_type == 'pdf':
        return process_pdf_file(file_path)
    elif file_type in ['mp3', 'wav', 'ogg']:
        return process_voice_file(file_path, file_type)
    else:
        # For unknown file types, try to read as text
        return process_text_file(file_path)

def process_text_file(file_path):
    """Process a text file."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            return f.read()
    except Exception as e:
        return f"Error processing text file: {str(e)}"

def process_pdf_file(file_path):
    """Extract text from a PDF file."""
    text = ""
    try:
        with open(file_path, 'rb') as f:
            pdf_reader = PyPDF2.PdfReader(f)
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += page.extract_text() + "\n"
        return text
    except Exception as e:
        return f"Error processing PDF file: {str(e)}"

def process_voice_file(file_path, file_type):
    """Convert voice to text using speech recognition."""
    recognizer = sr.Recognizer()
    
    try:
        with sr.AudioFile(file_path) as source:
            audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data)
            return text
    except Exception as e:
        return f"Error processing voice file: {str(e)}"

def extract_text_from_file(file_path, file_type):
    """Extract text from a file based on its type."""
    return process_file(file_path, file_type)

def update_file_content(file, new_content):
    """Update the content of an encrypted file."""
    # In a real DSSE system, this would use a specialized algorithm
    # For demonstration, we'll re-encrypt the file
    
    # Generate a master key (in a real system, this would be securely shared)
    master_key = os.urandom(32)
    
    # Update the encrypted file
    update_encrypted_file(file, new_content, master_key)
    
    # Update the search index
    file_id = file.id
    
    # Clear existing index entries
    SearchIndex.query.filter_by(file_id=file_id).delete()
    
    # Create new index
    encrypted_index = create_search_index(new_content, master_key)
    
    # Update the file's index data
    file.index_data = encrypted_index
    
    db.session.commit()
