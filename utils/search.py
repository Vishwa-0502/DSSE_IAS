import re
import json
import hashlib
from models import SearchIndex, db
from utils.encryption import encrypt_search_index

def create_search_index(text_content, master_key):
    """Create a searchable index from text content."""
    index = {}
    
    # Convert to lowercase and tokenize
    words = re.findall(r'\b\w+\b', text_content.lower())
    
    # Build index with word positions
    for position, word in enumerate(words):
        if len(word) > 2:  # Skip very short words
            if word not in index:
                index[word] = []
            index[word].append(position)
    
    # Encrypt each index entry
    encrypted_index = {}
    for word, positions in index.items():
        keyword_hash, encrypted_entry = encrypt_search_index(word, positions, master_key)
        encrypted_index[keyword_hash] = encrypted_entry
        
        # Also save to database for server-side searching
        index_entry = SearchIndex(
            keyword_hash=keyword_hash,
            encrypted_locations=json.dumps(encrypted_entry)
        )
        db.session.add(index_entry)
    
    return encrypted_index

def search_file(file_path, keyword):
    """Search for a keyword in a decrypted file."""
    with open(file_path, 'r', errors='ignore') as f:
        content = f.read()
    
    # Convert keyword to lowercase for case-insensitive search
    keyword_lower = keyword.lower()
    content_lower = content.lower()
    
    # Find all occurrences
    matches = []
    start = 0
    while True:
        index = content_lower.find(keyword_lower, start)
        if index == -1:
            break
            
        # Get context (text before and after the match)
        context_start = max(0, index - 50)
        context_end = min(len(content), index + len(keyword) + 50)
        
        # Extract context with the keyword
        context = content[context_start:context_end]
        
        # Highlight the keyword in the context
        keyword_start = index - context_start
        keyword_end = keyword_start + len(keyword)
        highlighted_context = context[:keyword_start] + f"<strong>{context[keyword_start:keyword_end]}</strong>" + context[keyword_end:]
        
        matches.append({
            'position': index,
            'context': highlighted_context
        })
        
        start = index + len(keyword)
    
    return matches
