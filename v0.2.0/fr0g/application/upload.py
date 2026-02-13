from fr0g import HORIZON_URL, CHUNK_SIZE, MAX_ENTRIES_PER_ACCOUNT, MIME_FALLBACK
from fr0g.core.protocol import chunk, guess_mime_type, fr0gID2stellar, stellar2fr0gID, fr0gsecret2stellar,enable_id
from fr0g.application.tx_utils import retrieve_data, get_sequence_number, create_empty_transaction, append_manage_data_op, sign_transaction, submit_transaction, random_keypair, account_exists, keypair_from_seed
from fr0g.core.compression import gzip_compress_if_useful
from typing import List
import time
import gzip

class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'


def clear_index(fr0g_id: str, fr0g_secret: str, target_index: int):

    current_id = fr0g_id
    visited = set()
    removed = 0

    while current_id not in visited:
       
        visited.add(current_id)
       
        stellar_addr = fr0gID2stellar(current_id)


        if not account_exists(stellar_addr):
            print(f"Account {stellar_addr} does not exist → assuming already cleared / never existed")
          
            continue


        data = retrieve_data(current_id)
        
        keys_to_clear = []
        for key, _ in data:
            if key.startswith(f"fr0g:f{target_index}c") or key == f"fr0g:next_f{target_index}":
                keys_to_clear.append(key)

        if keys_to_clear:
            seq = get_sequence_number(stellar_addr) + 1
            i = 0
            while i < len(keys_to_clear):
                tx = create_empty_transaction(stellar_addr, seq)
                ops = 0
                while i < len(keys_to_clear) and ops < 100:
                    tx = append_manage_data_op(tx, keys_to_clear[i], None)
                    ops += 1
                    i += 1
                if ops > 0:
                    stellar_secret = fr0gsecret2stellar(fr0g_secret)
                    tx = sign_transaction(tx, stellar_secret)
                    submit_transaction(tx)
                    removed += ops
                    seq += 1
                    print(f"Cleared {ops} keys from {current_id} for index {target_index}")


        entries = {k: v for k, v in data}
        next_key = f"fr0g:next_f{target_index}"
        if next_key in entries:
            next_id = entries[next_key]
            if isinstance(next_id, str) and next_id.startswith("fr0g"):
                current_id = next_id
                continue
        break

    print(f"Total keys cleared for index {target_index}: {removed}")
    return removed


def upload(inp: bytes, fr0g_secret: str, index: int | str = 0) -> List[str]:
    compressible_mimes = {
        "text/html", "text/plain", "application/json", "text/css",
        "application/javascript", "text/xml", "application/xml"
    }
    is_compressed=False
    if not inp:
        raise ValueError("Empty content")
    
    
    
    mime_type = guess_mime_type(inp)
    if mime_type in compressible_mimes:
       inp=gzip.compress(inp)
       is_compressed=True
    print(f"Type: {mime_type}")


    current_secret = fr0g_secret
    stellar_pub, _ = keypair_from_seed(bytes.fromhex(current_secret))
    current_id = stellar2fr0gID(stellar_pub)
    stellar_addr = fr0gID2stellar(current_id)


    if not account_exists(stellar_addr):
        print(f"Root account {stellar_addr} ({current_id}) does not exist → funding...")
        try:
            enable_id(current_id, current_secret,airdrop_only=True) 

            import time
            time.sleep(4)
        except Exception as e:
            raise RuntimeError(f"Cannot activate root account {current_id}: {e}")


    if not account_exists(stellar_addr):
        raise RuntimeError(
            f"Failed to activate root account {stellar_addr}. "
            "Check friendbot connection or try again later."
        )

    all_ids = [current_id]

    chunks = chunk(inp)
    total_chunks = len(chunks)
    if total_chunks == 0:
        print("No chunks to upload (empty after padding?)")
        return all_ids

    chunk_idx = 0
    chunk_num = 1


    if isinstance(index, str) and index.lower() == "next":
        file_count = get_file_count(current_id)
        target_index = file_count + 1 if file_count > 0 else 0
        print(f"Auto-index: using next → #{target_index}")
    elif isinstance(index, int) and index >= 0:
        target_index = index
        print(f"Using specified index → #{target_index}")
    else:
        raise ValueError("index must be int >= 0 or 'next'")


    print(f"Checking for existing content at index {target_index}...")
    try:
        cleared = clear_index(current_id, current_secret, target_index)
        print(f"Cleared {cleared} keys from previous content (index {target_index})")
    except:
           pass

    MAX_ENTRIES_PER_ACCOUNT = 500
    MAX_OPS_PER_TX = 100

    while chunk_idx < total_chunks:

        try:
            current_entries = len(retrieve_data(current_id))
        except Exception as e:
            print(f"Cannot read current entries from {current_id}: {e}")
            raise

        available_slots = MAX_ENTRIES_PER_ACCOUNT - current_entries
        if available_slots <= 1: 
            print(f"No space left in {current_id} ({available_slots} slots) → creating new child account")
            new_id, new_secret = random_keypair(enabled=True) 
            all_ids.append(new_id)


            stellar_addr = fr0gID2stellar(current_id)
            try:
                seq = get_sequence_number(stellar_addr) + 1
                tx = create_empty_transaction(stellar_addr, seq)
                link_key = f"fr0g:next_f{target_index}"
                tx = append_manage_data_op(tx, link_key, new_id.encode("ascii"))
                stellar_secret = fr0gsecret2stellar(current_secret)
                tx = sign_transaction(tx, stellar_secret)
                submit_transaction(tx)
                print(f"Linked to new child: {new_id}")
            except Exception as e:
                raise RuntimeError(f"Failed to link child account: {e}")


            current_id = new_id
            current_secret = new_secret
            stellar_addr = fr0gID2stellar(current_id)
            current_entries = 0
            available_slots = MAX_ENTRIES_PER_ACCOUNT


        max_chunks_this_account = min(available_slots - 1, total_chunks - chunk_idx)

        print(f"Uploading up to {max_chunks_this_account} chunks to {current_id} "
              f"(slots available: {available_slots})")

        while max_chunks_this_account > 0 and chunk_idx < total_chunks:
            try:
                stellar_addr = fr0gID2stellar(current_id)
                seq = get_sequence_number(stellar_addr) + 1
                tx = create_empty_transaction(stellar_addr, seq)
                ops_this_tx = 0

                while ops_this_tx < MAX_OPS_PER_TX and max_chunks_this_account > 0 and chunk_idx < total_chunks:
                    chunk_data = chunks[chunk_idx]
                    key = f"fr0g:f{target_index}c{chunk_num}:{mime_type}"
                    if is_compressed:
                       key=key+'+gzip'
                    tx = append_manage_data_op(tx, key, chunk_data)
                    ops_this_tx += 1
                    chunk_idx += 1
                    chunk_num += 1
                    max_chunks_this_account -= 1

                if ops_this_tx > 0:
                    stellar_secret = fr0gsecret2stellar(current_secret)
                    tx = sign_transaction(tx, stellar_secret)
                    submit_transaction(tx)
                    progress = (chunk_idx / total_chunks) * 100
                    print(f"{color.BOLD}Upload progress: {progress:.2f}%{color.END} - {chunk_idx}/{total_chunks} chunks - "
                          f"account {current_id} - file #{target_index}")

            except Exception as e:
                print(f"Error during upload to {current_id}: {e}")
                raise
    print(f"Upload completed. Total accounts used: {len(all_ids)}")
    return all_ids




def remove_file(fr0g_id: str, file_index: int, fr0g_secret: str) -> int:
    current_id = fr0g_id
    visited = set()
    removed_count = 0
    MAX_OPS_PER_TX = 100
    stellar_pubkey, _ = keypair_from_seed(bytes.fromhex(fr0g_secret))
    if stellar2fr0gID(stellar_pubkey) != fr0g_id:
        raise ValueError("Il secret fornito non corrisponde all'ID fr0g iniziale")
    while current_id not in visited:
        visited.add(current_id)
        stellar_addr = fr0gID2stellar(current_id)
        data_entries = retrieve_data(current_id)
        if not data_entries:
            break
        keys_to_remove: List[str] = []
        for key, _ in data_entries:
            if key.startswith(f"fr0g:f{file_index}c"):
                keys_to_remove.append(key)
        next_key = f"fr0g:next_f{file_index}"
        if any(k == next_key for k, _ in data_entries):
            keys_to_remove.append(next_key)
        if not keys_to_remove:
            pass
        else:
            seq = get_sequence_number(stellar_addr) + 1
            i = 0
            while i < len(keys_to_remove):
                tx = create_empty_transaction(stellar_addr, seq)
                ops_this_tx = 0
                while i < len(keys_to_remove) and ops_this_tx < MAX_OPS_PER_TX:
                    key = keys_to_remove[i]
                    tx = append_manage_data_op(tx, key, None)
                    ops_this_tx += 1
                    i += 1
                if ops_this_tx > 0:
                    stellar_secret = fr0gsecret2stellar(fr0g_secret)
                    try:
                        tx = sign_transaction(tx, stellar_secret)
                        submit_transaction(tx)
                        removed_count += ops_this_tx
                        seq += 1
                        print(f"Removed {ops_this_tx} entries from {current_id} (total: {removed_count})")
                    except Exception as e:
                        print(f"Error during removal from {current_id}: {e}")
                        return removed_count
        entry_dict = {k: v for k, v in data_entries}
        next_key = f"fr0g:next_f{file_index}"
        if next_key in entry_dict:
            try:
                next_id = entry_dict[next_key].decode("ascii")
                if next_id.startswith("fr0g") and next_id != current_id:
                    current_id = next_id
                    continue
            except:
                break
        else:
            break
    return removed_count

def remove_all(fr0g_id: str, fr0g_secret: str) -> int:
    current_id = fr0g_id
    visited = set()
    total_removed = 0
    MAX_OPS_PER_TX = 100
    stellar_pubkey, _ = keypair_from_seed(bytes.fromhex(fr0g_secret))
    if stellar2fr0gID(stellar_pubkey) != fr0g_id:
        raise ValueError("The secret does not match the initial fr0g ID")
    while current_id not in visited:
        visited.add(current_id)
        stellar_addr = fr0gID2stellar(current_id)
        data_entries = retrieve_data(current_id)
        if not data_entries:
            break
        keys_to_remove: List[str] = [
            key for key, _ in data_entries
            if key.startswith("fr0g:")
        ]
        if not keys_to_remove:
            break
        seq = get_sequence_number(stellar_addr) + 1
        i = 0
        while i < len(keys_to_remove):
            tx = create_empty_transaction(stellar_addr, seq)
            ops_this_tx = 0
            while i < len(keys_to_remove) and ops_this_tx < MAX_OPS_PER_TX:
                key = keys_to_remove[i]
                tx = append_manage_data_op(tx, key, None)
                ops_this_tx += 1
                i += 1
            if ops_this_tx > 0:
                stellar_secret = fr0gsecret2stellar(fr0g_secret)
                try:
                    tx = sign_transaction(tx, stellar_secret)
                    submit_transaction(tx)
                    total_removed += ops_this_tx
                    seq += 1
                    print(f"Removed {ops_this_tx} entries from {current_id} (total: {total_removed})")
                except Exception as e:
                    print(f"Error on {current_id}: {e}")
                    return total_removed
        entry_dict = {k: v for k, v in data_entries}
        next_id = None
        for key, value in entry_dict.items():
            if key.startswith("fr0g:next_f"):
                try:
                    candidate = value.decode("ascii")
                    if candidate.startswith("fr0g") and candidate != current_id:
                        next_id = candidate
                        break
                except:
                    pass
        if next_id:
            current_id = next_id
        else:
            break
    return total_removed



