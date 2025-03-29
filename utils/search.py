import re
import json
import hashlib
import logging
from models import SearchIndex, db
from utils.encryption import encrypt_search_index

def create_search_index(text_content, master_key, file_id=None):
    """Create a searchable index from text content."""
    logger = logging.getLogger(__name__)
    logger.info(f"Creating search index for text of length {len(text_content)} characters")
    
    index = {}
    
    # Convert to lowercase and tokenize
    words = re.findall(r'\b\w+\b', text_content.lower())
    logger.info(f"Extracted {len(words)} words from content")
    
    # Build index with word positions
    word_count = 0
    for position, word in enumerate(words):
        if len(word) > 2:  # Skip very short words
            if word not in index:
                index[word] = []
                word_count += 1
            index[word].append(position)
    
    logger.info(f"Built index with {word_count} unique words (excluding very short words)")
    
    # Encrypt each index entry
    encrypted_index = {}
    db_entries_count = 0
    
    for word, positions in index.items():
        keyword_hash, encrypted_entry = encrypt_search_index(word, positions, master_key)
        encrypted_index[keyword_hash] = encrypted_entry
        logger.debug(f"Indexed word with hash {keyword_hash[:10]}..., {len(positions)} positions")
        
        # Also save to database for server-side searching if file_id is provided
        if file_id is not None:
            try:
                index_entry = SearchIndex(
                    file_id=file_id,
                    keyword_hash=keyword_hash,
                    encrypted_locations=json.dumps(encrypted_entry)
                )
                db.session.add(index_entry)
                db_entries_count += 1
                
                # Flush after every 100 entries to avoid large transactions
                if db_entries_count % 100 == 0:
                    db.session.flush()
                    logger.debug(f"Flushed {db_entries_count} search index entries to database")
            except Exception as e:
                logger.error(f"Error adding search index for word hash {keyword_hash[:10]}...: {str(e)}")
    
    logger.info(f"Created encrypted index with {len(encrypted_index)} entries and {db_entries_count} database records")
    
    # Final flush to ensure all entries are in the database
    if file_id is not None and db_entries_count > 0:
        try:
            db.session.flush()
            logger.info(f"Flushed final batch of search index entries to database")
        except Exception as e:
            logger.error(f"Error during final flush of search index entries: {str(e)}")
    
    return encrypted_index

def search_file(file_path_or_content, keyword):
    """Search for a keyword in a decrypted file or string content.
    
    Args:
        file_path_or_content: Either a file path (str) or a file-like object (StringIO)
        keyword: The keyword to search for
    """
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Check if the input is a file path or already content
        if isinstance(file_path_or_content, str) and not hasattr(file_path_or_content, 'read'):
            # It's a file path
            logger.info(f"Reading from file path: {file_path_or_content}")
            with open(file_path_or_content, 'r', errors='ignore') as f:
                content = f.read()
        else:
            # It's a file-like object (StringIO) or a string
            if hasattr(file_path_or_content, 'read'):
                logger.info("Reading from file-like object")
                # Reset the cursor to the beginning of the file if possible
                if hasattr(file_path_or_content, 'seek'):
                    file_path_or_content.seek(0)
                content = file_path_or_content.read()
            else:
                # It's directly a string
                logger.info("Using content string directly")
                content = str(file_path_or_content)
        
        logger.info(f"Searching for keyword: '{keyword}' in content of length: {len(content)}")
        
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
        
        logger.info(f"Found {len(matches)} matches for '{keyword}'")
        return matches
    except Exception as e:
        logger.error(f"Search error: {str(e)}", exc_info=True)
        return [{'position': 0, 'context': f"Error during search: {str(e)}"}]
