from fr0g.application.tx_utils import retrieve_data, fr0gID2stellar
from typing import Tuple, Optional
import gzip

def get_mime_type(fr0g_id: str, file_index: int = 0) -> Optional[str]:

    current_id = fr0g_id
    visited = set()

    while current_id not in visited:
        visited.add(current_id)
        data_entries = retrieve_data(current_id)
        if not data_entries:
            break

        entry_dict = {k: v for k, v in data_entries}

        for key, _ in data_entries:
            if not key.startswith(f"fr0g:f{file_index}c"):
                continue


            try:
                rest = key.split("c", 1)[1]
                subparts = rest.split(":", 1) 
                if len(subparts) < 2:
                    continue

                chunk_num_str = subparts[0]
                mime_candidate = subparts[1].strip()



                if chunk_num_str.isdigit():
                    if mime_candidate:
                       return mime_candidate

            except (IndexError, ValueError):
                continue


        next_key = f"fr0g:next_f{file_index}"
        if next_key in entry_dict:
            try:
                next_id = entry_dict[next_key]
                if isinstance(next_id, str) and next_id.startswith("fr0g") and next_id != current_id:
                    current_id = next_id
                    continue
            except:
                break
        else:
            break

    return None

def get_content(id: str, index: int = 0):
    chunks = []  # [(chunk_num, bytes)]
    retrieve = retrieve_data(id)    
    for entry in retrieve:
        key, value_bytes = entry        
        if not key.startswith(f'fr0g:f{index}c'):
            continue        
        try:
            rest = key.split("c", 1)[1]
            chunk_num_str = rest.split(":", 1)[0]
            chunk_num = int(chunk_num_str)
            chunks.append((chunk_num, value_bytes))
        except:
            continue    
    if not chunks:
        return None, None    
    chunks.sort(key=lambda x: x[0])    
    full = b''.join(val for _, val in chunks)
    while full and full[-1] == 0xFF:
        full = full[:-1]    
    mime = get_mime_type(id)
    is_gzipped = "+gzip" in mime
    mime_clean = mime.replace("+gzip", "")    
    if is_gzipped:
        try:
            full = gzip.decompress(full)
        except Exception as e:
            print(f"Gzip decompress failed: {e}")
            return None, None    
    return full, mime_clean

