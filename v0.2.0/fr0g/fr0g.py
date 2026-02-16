# Copyright 2026 0ut0flin3
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from ed25519_ext import SigningKey
import base64
import requests
import struct
import secrets
from typing import Dict, Any, List, Tuple, Optional
import hashlib
import gzip
import time
class colors:
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
TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_ID = hashlib.sha256(TESTNET_PASSPHRASE.encode()).digest()
ENVELOPE_TYPE_TX         = b'\x00\x00\x00\x02'
PUBLIC_KEY_TYPE_ED25519  = b'\x00\x00\x00\x00'
SIGNATURE_HINT_LENGTH    = 4
VERSION_BYTE_ACCOUNT_ID = 6 << 3
VERSION_BYTE_SECRET_SEED = 18 << 3
CONTENT_INDEXERS = {
    'html':    'fr0gey3nkjwxfi3olj2opkjwzxg2prjxwyld3rxthfuzqd5ssyzisbr3fcbg',
    'video':   'fr0gmypk54u3b5zytuzhwdbpxcyems234siebxa5wf2htz62smg4hbrtz5ag',
    'images':  'fr0gar7b4wscthfrqofckuq22clb3usofiud75gozxe26mqavyisrc5bemcg',
    'code':    'fr0g64n6okdmub2vqiiqmupwdtclsqakkbm3idbaz6c3kliddivpgfeetldg',
    'raw':     'fr0gcqkdfplmirjr5wxkez75mubdwow3i2ishskhgnesq4iyiishafeef2dg',
}
MIME_TO_CATEGORY = {
    'text/html': 'html',
    'application/xhtml+xml': 'html',    
    'video/mp4': 'video',
    'video/webm': 'video',
    'video/ogg': 'video',
    'video/quicktime': 'video',
    'video/x-matroska': 'video',    
    'image/jpeg': 'images',
    'image/png': 'images',
    'image/gif': 'images',
    'image/webp': 'images',
    'image/svg+xml': 'images',
    'image/bmp': 'images',
    'image/tiff': 'images',
    'text/plain': 'code',
    'application/json': 'code',
    'text/css': 'code',
    'application/javascript': 'code',
    'text/javascript': 'code',
    'text/x-python': 'code',
    'application/x-python-code': 'code',
    'text/x-c': 'code',
    'text/x-c++': 'code',
    'application/x-sh': 'code',
    'text/x-shellscript': 'code',
    'application/xml': 'code',
    'text/xml': 'code',
}
def get_indexerID_from_mimetype(mime_type: str | None) -> str:
    """
    Returns the corresponding indexer fr0g ID based on the MIME type.
    Falls back to 'raw' if the MIME type is unknown or None.

    Args:
        mime_type: MIME type string (e.g. 'image/jpeg', 'video/mp4', 'text/html')

    Returns:
        str: One of the fixed indexer IDs from CONTENT_INDEXERS
    """
    if not mime_type:
        return CONTENT_INDEXERS['raw']

    # Normalize MIME (remove parameters like charset, +gzip, etc.)
    mime_clean = mime_type.lower().split(';')[0].split('+')[0].strip()

    # Direct match
    category = MIME_TO_CATEGORY.get(mime_clean)

    # Prefix fallback
    if not category:
        if mime_clean.startswith('text/html') or mime_clean.startswith('application/xhtml'):
            category = 'html'
        elif mime_clean.startswith('video/'):
            category = 'video'
        elif mime_clean.startswith('image/'):
            category = 'images'
        elif mime_clean.startswith('text/') or mime_clean in (
            'application/json', 'application/javascript', 'text/css', 'application/xml'
        ):
            category = 'code'
        else:
            category = 'raw'

    return CONTENT_INDEXERS.get(category, CONTENT_INDEXERS['raw'])
def crc16_xmodem(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc
def strkey_encode(version_byte: int, payload: bytes) -> str:
    data = bytes([version_byte]) + payload
    checksum = struct.pack("<H", crc16_xmodem(data))
    encoded = base64.b32encode(data + checksum)
    return encoded.decode("ascii")
def strkey_decode(version_byte: int, encoded: str) -> bytes:
    padded = encoded + "=" * ((8 - len(encoded) % 8) % 8)
    raw = base64.b32decode(padded)
    if raw[0] != version_byte:
        raise ValueError("Invalid version byte")
    payload = raw[1:-2]
    checksum = raw[-2:]
    if struct.pack("<H", crc16_xmodem(raw[:-2])) != checksum:
        raise ValueError("Invalid checksum")
    return payload
def keypair_from_seed(seed):
    sk = SigningKey(seed)
    vk_obj = sk.get_verifying_key()
    vk = vk_obj.to_bytes()
    secret = strkey_encode(VERSION_BYTE_SECRET_SEED, seed)
    public_key = strkey_encode(VERSION_BYTE_ACCOUNT_ID, vk)
    return public_key, secret
def enable_id(fr0g_id,fr0g_secret,airdrop_only=False):
    address=fr0g_id[4:][::-1].upper()
    url = f"https://friendbot.stellar.org?addr={address}"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36",
         "Accept": "application/json",
    }
    r=requests.get(url, headers=headers)
    r.raise_for_status()
    if airdrop_only==False:
       set_value(f':{fr0g_id}:',b'\x01', fr0g_secret)
def stellar2fr0gID(stellar_address):
    return 'fr0g' + stellar_address.lower()[::-1]
def fr0gID2stellar(fr0g_id):
    return fr0g_id[4:][::-1].upper()
def fr0gsecret2stellar(fr0g_secret):
    return strkey_encode(VERSION_BYTE_SECRET_SEED, bytes.fromhex(fr0g_secret))
def random_keypair(enabled=False):
    seed = secrets.token_bytes(32)
    stellar_pubkey, stellar_secret = keypair_from_seed(seed)
    fr0g_id = stellar2fr0gID(stellar_pubkey)
    if enabled:
       try: 
           enable_id(fr0g_id,seed.hex())
       except:
              raise Exception('Connection error: Fr0g ID was created but not initialized')
    return fr0g_id, seed.hex()         
def chunk(inp: bytes):
    inp = list(inp)
    while len(inp) % 64 != 0:
        inp.append(0xFF)
    n_chunks = int(len(inp) / 64)
    j = 0
    i = 64
    out = []
    for x in range(0, n_chunks):
        out.append(bytes(inp[j:i]))
        j += 64
        i += 64
    return out
def get_sequence_number(account_id):
    r = requests.get(f"{HORIZON_URL}/accounts/{account_id}")
    seq = int(r.json()["sequence"]) if r.ok else 0
    return seq
def create_empty_transaction(source_account: str, sequence: int, memo: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if memo is None:
        memo = {"type": "none"}
    tx = {
        "source_account": source_account,
        "sequence": sequence,
        "fee": 100,
        "time_bounds": None,
        "memo": memo,
        "operations": [],
        "network_id": NETWORK_ID,
        "tx_xdr": None,
        "tx_hash": None
    }
    return tx
def append_manage_data_op(
    tx: Dict[str, Any],
    key: str,
    value: bytes | str | None = None
) -> Dict[str, Any]:
    if len(key) > 64:
       raise ValueError("ManageData key max length = 64 bytes")
    if isinstance(value, str):
        value = value.encode("utf-8")
    if value is not None and len(value) > 64:
       raise ValueError("ManageData value max length = 64 bytes")
    op = {
        "type": "manage_data",
        "data": {
            "key": key,
            "value": value
        }
    }
    tx["operations"].append(op)
    return tx
def append_payment_op(
    tx: Dict[str, Any],
    destination: str,
    amount_stroops: int
) -> Dict[str, Any]:
    op = {
        "type": "payment",
        "destination": destination,
        "asset": "native",
        "amount": amount_stroops
    }
    tx["operations"].append(op)
    return tx
def append_set_options_op(
    tx: Dict[str, Any]
) -> Dict[str, Any]:
    op = {
        "type": "set_options"
    }
    tx["operations"].append(op)
    return tx
def sign_transaction(tx: Dict[str, Any], secret_seed: str) -> Dict[str, Any]:
    secret_seed = secret_seed.upper().replace(" ", "").replace("-", "")
    padded = secret_seed + "=" * ((8 - len(secret_seed) % 8) % 8)
    raw = base64.b32decode(padded)
    if len(raw) != 35:
        raise ValueError("Invalid secret seed")
    secret_seed_bytes = raw[1:33]
    signing_key = SigningKey(secret_seed_bytes)
    public_key_bytes = signing_key.get_verifying_key().to_bytes()
    source_account_xdr = PUBLIC_KEY_TYPE_ED25519 + public_key_bytes
    fee_xdr = struct.pack(">I", tx["fee"] * len(tx["operations"]))
    seq_num_xdr = struct.pack(">Q", tx["sequence"])
    if tx["memo"]["type"] == "none":
        memo_xdr = struct.pack(">I", 0)
    elif tx["memo"]["type"] == "text":
        text = tx["memo"]["text"].encode("utf-8")
        if len(text) > 28:
            raise ValueError("Text memo max length = 28 bytes")
        memo_xdr = struct.pack(">I", 1) + struct.pack(">I", len(text)) + text + b"\x00" * ((4 - len(text) % 4) % 4)
    else:
        raise ValueError("Unsupported memo type")
    time_bounds_xdr = struct.pack(">I", 0)
    ops_xdr = b""
    for op in tx["operations"]:
        op_source_xdr = struct.pack(">I", 0)
        if op["type"] == "manage_data":
            key_bytes = op["data"]["key"].encode("ascii")
            key_xdr = struct.pack(">I", len(key_bytes)) + key_bytes + b"\x00" * ((4 - len(key_bytes) % 4) % 4)
            if op["data"]["value"] is None:
                value_xdr = struct.pack(">I", 0)
            else:
                val = op["data"]["value"]
                value_xdr = (
                    struct.pack(">I", 1) +
                    struct.pack(">I", len(val)) +
                    val +
                    b"\x00" * ((4 - len(val) % 4) % 4)
                )
            ops_xdr += (
                op_source_xdr +
                struct.pack(">I", 10) +
                key_xdr +
                value_xdr
            )
        elif op["type"] == "payment":
            dest_bytes = strkey_decode(VERSION_BYTE_ACCOUNT_ID, op["destination"])
            asset_xdr = struct.pack(">I", 0)
            amount_xdr = struct.pack(">q", op["amount"])
            ops_xdr += (
                op_source_xdr +
                struct.pack(">I", 1) +
                PUBLIC_KEY_TYPE_ED25519 + dest_bytes +
                asset_xdr +
                amount_xdr
            )
        elif op["type"] == "set_options":
            ops_xdr += (
                op_source_xdr +
                struct.pack(">I", 5) +
                struct.pack(">I", 0) * 9
            )
        else:
            raise ValueError("Unsupported operation type")
    tx_body_xdr = (
        source_account_xdr +
        fee_xdr +
        seq_num_xdr +
        time_bounds_xdr +
        struct.pack(">I", len(tx["operations"])) +
        ops_xdr +
        struct.pack(">I", 0)
    )
    memo_xdr_pos = len(source_account_xdr + fee_xdr + seq_num_xdr + time_bounds_xdr)
    tx_body_xdr = tx_body_xdr[:memo_xdr_pos] + memo_xdr + tx_body_xdr[memo_xdr_pos:]
    payload = NETWORK_ID + ENVELOPE_TYPE_TX + tx_body_xdr
    tx_hash = hashlib.sha256(payload).digest()
    signature = signing_key.sign(tx_hash)
    hint = public_key_bytes[-SIGNATURE_HINT_LENGTH:]
    envelope_xdr = (
        tx_body_xdr +
        struct.pack(">I", 1) +
        hint +
        struct.pack(">I", len(signature)) +
        signature
    )
    tx["tx_xdr"] = base64.b64encode(envelope_xdr).decode("ascii")
    tx["tx_hash"] = tx_hash.hex()
    return tx
def submit_transaction(tx: dict, horizon_url: str = HORIZON_URL):
    payload = {"tx": tx["tx_xdr"]}
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    response = requests.post(
        f"{horizon_url}/transactions",
        data=payload,
        headers=headers
    )
    if not response.ok:
        print(response.text)
        raise ConnectionError("Horizon error")
    return response.json()
def retrieve_data(fr0g_id):
    r = requests.get(f"{HORIZON_URL}/accounts/{fr0gID2stellar(fr0g_id)}")
    account_info = r.json()
    data_entries = account_info.get("data", {})
    decoded_entries = {k: base64.b64decode(v) for k, v in data_entries.items()}     
    result = [(key, value) for key, value in decoded_entries.items()]
    return result
def set_value(key:str,value:bytes,fr0g_secret):
    stellar_address,stellar_secret=keypair_from_seed(bytes.fromhex(fr0g_secret))[0]  ,fr0gsecret2stellar(fr0g_secret)
    tx=create_empty_transaction(stellar_address,get_sequence_number(stellar_address)+1)
    tx=append_manage_data_op(tx,key,value)
    tx=sign_transaction(tx,stellar_secret)
    submit_transaction(tx)    
def get_file_count(fr0g_id):
    data = retrieve_data(fr0g_id)
    l = [0]
    for x in data:
        if 'fr0g:f' in x[0]:
            try:
                file_str = x[0].split('fr0g:f')[1].split('c')[0]
                num = int(file_str)
                l.append(num)
            except ValueError:
                pass
    return max(l)
def guess_mime_type(data: bytes) -> str:
    if len(data) < 4:
        return "application/octet-stream"
    header = data[:12]
    if header.startswith(b'\xFF\xD8\xFF'):
        return "image/jpeg"
    if header.startswith(b'\x89PNG\r\n\x1A\n'):
        return "image/png"
    if header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
        return "image/gif"
    if header.startswith(b'RIFF') and header[8:12] == b'WEBP':
        return "image/webp"
    if header.startswith(b'BM'):
        return "image/bmp"
    if header.startswith(b'%PDF-'):
        return "application/pdf"
    if header.startswith(b'\x00\x00\x00\x1Cftyp') or \
       header.startswith(b'\x00\x00\x00\x18ftyp'):
        return "video/mp4"
    if header.startswith(b'ID3'):
        return "audio/mpeg"
    if header.startswith(b'OggS'):
        return "audio/ogg"
    if header.startswith(b'PK\x03\x04') or header.startswith(b'PK\x05\x06'):
        return "application/zip"
    if header.startswith(b'Rar!\x1A\x07\x00'):
        return "application/x-rar-compressed"
    if header.startswith(b'\x1F\x8B'):
        return "application/gzip"
    if header.startswith(b'<!DOCTYPE html') or header.startswith(b'<html'):
        return "text/html"
    if header.startswith(b'<?xml'):
        return "application/xml"
    try:
        data[:1024].decode('utf-8')
        if b'{' in data[:128] or b'[' in data[:128]:
            return "application/json"
        return "text/plain"
    except UnicodeDecodeError:
        pass
    return "application/octet-stream"
def clear_index(fr0g_id: str, fr0g_secret: str, target_index: int):
    current_id = fr0g_id
    visited = set()
    removed = 0
    while current_id not in visited:
       visited.add(current_id)
       stellar_addr = fr0gID2stellar(current_id)
       if not account_exists(stellar_addr):
            print(f"Account {stellar_addr} does not exist - assuming already cleared / never existed")
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
                    print(colors.GREEN + f"Cleared {ops} keys from {current_id} for index {target_index}" + colors.END)
       entries = {k: v for k, v in data}
       next_key = f"fr0g:next_f{target_index}"
       if next_key in entries:
            next_id = entries[next_key]
            if isinstance(next_id, str) and next_id.startswith("fr0g"):
                current_id = next_id
                continue
       break
    print(colors.GREEN + f"Total keys cleared for index {target_index}: {removed}" + colors.END)
    return removed
def gzip_compress_if_useful(
    data: bytes,
    mime_type: str,
    min_savings_percent: float = 5.0,
    compression_level: int = 6
) -> Tuple[bytes, bool]:
    if not data:
        return b"", False
    compressible_prefixes = (
        'text/', 'application/json', 'application/javascript', 'application/xml',
        'application/xhtml+xml', 'image/svg+xml'
    )
    is_potentially_compressible = any(mime_type.lower().startswith(p) for p in compressible_prefixes)
    if not is_potentially_compressible:
        return data, False
    try:
        compressed = gzip.compress(data, compresslevel=compression_level)
        original_size = len(data)
        compressed_size = len(compressed)
        savings = (original_size - compressed_size) / original_size * 100 if original_size > 0 else 0
        if savings >= min_savings_percent:
            print(colors.GREEN + f"Gzip useful: compressing... {original_size} -> {compressed_size} bytes " + colors.END+f"(savings:{savings})")
            return compressed, True
        else:
            print(colors.YELLOW + f"Gzip not useful: skipping compression...)" + colors.END)
            return data, False
    except Exception as e:
        print(colors.RED + f"Error during gzip compression: {e}" + colors.END)
        return data, False
def account_exists(address: str) -> bool:
    try:
        url = f"{HORIZON_URL}/accounts/{address}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            print(colors.RED + f"Unexpected status code checking account {address}: {response.status_code}" + colors.END)
            return False
    except Exception as e:
        print(colors.RED + f"Error checking account existence {address}: {str(e)}" + colors.END)
        return False
def upload(inp: bytes, fr0g_secret: str, index: int | str = 0, make_discoverable: bool = True) -> List[str]:
    if not inp:
        raise ValueError("Empty content")
    mime_type = guess_mime_type(inp)
    print(colors.BLUE + f"Type: {mime_type}" + colors.END)
    current_secret = fr0g_secret
    stellar_pub, _ = keypair_from_seed(bytes.fromhex(current_secret))
    current_id = stellar2fr0gID(stellar_pub)
    stellar_addr = fr0gID2stellar(current_id)
    if not account_exists(stellar_addr):
        print(colors.YELLOW + f"Root account {stellar_addr} ({current_id}) does not exist - funding..." + colors.END)
        try:
            enable_id(current_id, current_secret, airdrop_only=True)
            time.sleep(4)
        except Exception as e:
            raise RuntimeError(f"Cannot activate root account {current_id}: {e}")
    if not account_exists(stellar_addr):
        raise RuntimeError(f"Failed to activate root account {stellar_addr}. Check friendbot connection or try again later.")
    all_ids = [current_id]
    if isinstance(index, str) and index.lower() == "next":
        file_count = get_file_count(current_id)
        target_index = file_count + 1 if file_count > 0 else 0
        print(colors.BLUE + f"Auto-index: using next - #{target_index}" + colors.END)
    elif isinstance(index, int) and index >= 0:
        target_index = index
        print(colors.BLUE + f"Using specified index - #{target_index}" + colors.END)
    else:
        raise ValueError("index must be int >= 0 or 'next'")
    compressed_data, was_compressed = gzip_compress_if_useful(inp, mime_type)
    if was_compressed:
        print(colors.GREEN + f"Gzip compressed: {len(inp)} → {len(compressed_data)} bytes ({(len(inp)-len(compressed_data))/len(inp)*100:.1f}% savings)" + colors.END)
        data_to_upload = compressed_data
        mime_type += "+gzip"
    else:
        data_to_upload = inp
    chunks = chunk(data_to_upload)
    total_chunks = len(chunks)
    if total_chunks == 0:
        print(colors.YELLOW + "No chunks to upload (empty after padding?)" + colors.END)
        return all_ids
    chunk_idx = 0
    chunk_num = 1
    print(colors.BLUE + f"Checking for existing content at index {target_index}..." + colors.END)
    try:
        cleared = clear_index(current_id, current_secret, target_index)
        print(colors.GREEN + f"Cleared {cleared} keys from previous content (index {target_index})" + colors.END)
    except:
        pass
    MAX_ENTRIES_PER_ACCOUNT = 500
    MAX_OPS_PER_TX = 100
    while chunk_idx < total_chunks:
        try:
            current_entries = len(retrieve_data(current_id))
        except Exception as e:
            print(colors.RED + f"Cannot read current entries from {current_id}: {e}" + colors.END)
            raise
        available_slots = MAX_ENTRIES_PER_ACCOUNT - current_entries
        if available_slots <= 1:
            print(colors.YELLOW + f"No space left in {current_id} ({available_slots} slots) - creating new child account" + colors.END)
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
                print(colors.GREEN + f"Linked to new child: {new_id}" + colors.END)
            except Exception as e:
                raise RuntimeError(f"Failed to link child account: {e}")
            current_id = new_id
            current_secret = new_secret
            stellar_addr = fr0gID2stellar(current_id)
            current_entries = 0
            available_slots = MAX_ENTRIES_PER_ACCOUNT
        max_chunks_this_account = min(available_slots - 1, total_chunks - chunk_idx)
        print(colors.BLUE + f"Uploading up to {max_chunks_this_account} chunks to {current_id} (slots available: {available_slots})" + colors.END)
        while max_chunks_this_account > 0 and chunk_idx < total_chunks:
            try:
                stellar_addr = fr0gID2stellar(current_id)
                seq = get_sequence_number(stellar_addr) + 1
                tx = create_empty_transaction(stellar_addr, seq)
                ops_this_tx = 0
                while ops_this_tx < MAX_OPS_PER_TX and max_chunks_this_account > 0 and chunk_idx < total_chunks:
                    chunk_data = chunks[chunk_idx]
                    key = f"fr0g:f{target_index}c{chunk_num}:{mime_type}"
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
                    print(colors.YELLOW + f"Upload progress: {progress:.2f}% - {chunk_idx}/{total_chunks} chunks - account {current_id} - file #{target_index}" + colors.END)
            except Exception as e:
                print(colors.RED + f"Error during upload to {current_id}: {e}" + colors.END)
                raise
    print(colors.GREEN + f"Upload completed. Total accounts used: {len(all_ids)}" + colors.END)
######################################################à
    if make_discoverable:
       indexer_id=get_indexerID_from_mimetype(mime_type)
       print("guessed category id: "+indexer_id)
       send_text_memo(str(target_index),fr0gID2stellar(indexer_id),fr0gsecret2stellar(fr0g_secret),0)
###############################################
    return all_ids
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
def get_content(fr0g_id: str, file_index: int = 0) -> Tuple[Optional[bytes], Optional[str]]:
    collected_chunks = []
    mime_type = None
    current_id = fr0g_id
    visited = set()
    while current_id not in visited:
        visited.add(current_id)
        data_entries = retrieve_data(current_id)
        if not data_entries:
            break
        entry_dict = {k: v for k, v in data_entries}
        for key, value in entry_dict.items():
            if not key.startswith(f"fr0g:f{file_index}c"):
                continue
            try:
                rest = key.split("c", 1)[1]
                subparts = rest.split(":", 1)  
                if len(subparts) < 1:
                    continue
                chunk_num_str = subparts[0]
                if not chunk_num_str.isdigit():
                    continue
                chunk_num = int(chunk_num_str)
                collected_chunks.append((chunk_num, value))
                if mime_type is None and len(subparts) >= 2:
                    mime_type = subparts[1].strip()
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
    if not collected_chunks:
        return None, None
    collected_chunks.sort(key=lambda x: x[0])
    full = b"".join(data.encode('latin1') if isinstance(data, str) else data for _, data in collected_chunks)
    return full, mime_type
def remove_file(fr0g_id: str, file_index: int, fr0g_secret: str) -> int:
    current_id = fr0g_id
    visited = set()
    removed_count = 0
    MAX_OPS_PER_TX = 100
    stellar_pubkey, _ = keypair_from_seed(bytes.fromhex(fr0g_secret))
    if stellar2fr0gID(stellar_pubkey) != fr0g_id:
        raise ValueError("The secret provided does not match the initial fr0g ID")
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
                        print(colors.GREEN + f"Removed {ops_this_tx} entries from {current_id} (total: {removed_count})" + colors.END)
                    except Exception as e:
                        print(colors.RED + f"Error during removal from {current_id}: {e}" + colors.END)
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
                    print(colors.GREEN + f"Removed {ops_this_tx} entries from {current_id} (total: {total_removed})" + colors.END)
                except Exception as e:
                    print(colors.RED + f"Error on {current_id}: {e}" + colors.END)
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
def stroops_per_byte() -> Optional[float]:
    BASE_FEE_STROOPS       = 100
    AVG_BASE_FEE_STROOPS   = 2000
    CHUNK_SIZE_BYTES       = 64
    OPS_PER_TX             = 100
    MIN_BALANCE_XLM        = 1.0
    EXTRA_RESERVE_PER_DATA = 0.5
    try:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=stellar&vs_currencies=usd"
        r = requests.get(url, timeout=8)
        r.raise_for_status()
        data = r.json()
        if "stellar" in data and "usd" in data["stellar"]:
            xlm_usd = data["stellar"]["usd"]
        else:
            url_fallback = "https://api.coinpaprika.com/v1/tickers/xlm-stellar"
            r2 = requests.get(url_fallback, timeout=5)
            r2.raise_for_status()
            xlm_usd = r2.json()["quotes"]["USD"]["price"]
        print(colors.BLUE + f"Detected XLM price: ${xlm_usd:.6f}" + colors.END)
    except Exception as e:
        print(colors.RED + f"Error fetching XLM price: {e}" + colors.END)
        return None
    fee_per_chunk_stroops = AVG_BASE_FEE_STROOPS
    fee_per_tx_stroops = AVG_BASE_FEE_STROOPS * OPS_PER_TX
    chunks_per_tx      = OPS_PER_TX
    fee_per_byte       = fee_per_tx_stroops / (chunks_per_tx * CHUNK_SIZE_BYTES)
    stroops_per_xlm = 10_000_000
    reserve_for_data = 499 * EXTRA_RESERVE_PER_DATA
    total_reserve_xlm = MIN_BALANCE_XLM + reserve_for_data
    bytes_per_account = 499 * CHUNK_SIZE_BYTES
    reserve_stroops_per_byte = (total_reserve_xlm * stroops_per_xlm) / bytes_per_account
    total_stroops_per_byte = fee_per_byte + reserve_stroops_per_byte
    print(colors.BLUE + f"  → Estimated network fee:       {fee_per_byte:.2f} stroops/byte" + colors.END)
    print(colors.BLUE + f"  → Amortized reserve:   {reserve_stroops_per_byte:.2f} stroops/byte" + colors.END)
    print(colors.BLUE + f"  → Estimated total:         {total_stroops_per_byte:.2f} stroops/byte" + colors.END)
    return round(total_stroops_per_byte, 2)
def remaining_space(fr0g_id: str) -> int:
    from collections import deque
    visited = set()
    queue = deque([fr0g_id])
    all_accounts = set()
    remaining_slots_total = 0
    MAX_ENTRIES_PER_ACCOUNT = 500
    CHUNK_SIZE = 64
    MAX_TOTAL_ACCOUNTS = 8001  
    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        all_accounts.add(current)
        data_entries = retrieve_data(current)
        used_slots = 0
        for key, _ in data_entries:
            if key.startswith("fr0g:f") or key.startswith("fr0g:next_f"):
                used_slots += 1
        remaining_in_this = max(0, MAX_ENTRIES_PER_ACCOUNT - used_slots)
        remaining_slots_total += remaining_in_this
        for key, value in data_entries:
            if key.startswith("fr0g:next_f"):
                next_id = value
                if next_id.startswith("fr0g") and next_id not in visited:
                    queue.append(next_id)
    total_used_accounts = len(all_accounts)
    remaining_accounts = max(0, MAX_TOTAL_ACCOUNTS - total_used_accounts)
    remaining_bytes = remaining_slots_total * CHUNK_SIZE + remaining_accounts * (MAX_ENTRIES_PER_ACCOUNT * CHUNK_SIZE)
    return remaining_bytes
def get_c(id: str, index: int = 0):
    chunks = []  
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
    mime = get_mime_type(id) or "application/octet-stream"
    is_gzipped = "+gzip" in mime
    mime_clean = mime.replace("+gzip", "")
    if is_gzipped:
        try:
            full = gzip.decompress(full)
        except Exception as e:
            print(colors.RED + f"Gzip decompress failed: {e}" + colors.END)
            return None, None
    return full, mime_clean
def send_text_memo(mytext: str, address_to: str, secret_from: str, amount: float = 0):
    print("Make your content discoverable for others on the Fr0gNet...")
    if len(mytext.encode("utf-8")) > 28:
        pass
    stellar_from_secret = secret_from
    seed_bytes = strkey_decode(VERSION_BYTE_SECRET_SEED, secret_from)
    stellar_from = keypair_from_seed(seed_bytes)[0]
    if address_to.startswith("fr0g"):
        stellar_to = fr0gID2stellar(address_to)
    else:
        stellar_to = address_to
    seq = get_sequence_number(stellar_from) + 1
    memo = {"type": "text", "text": mytext}
    tx = create_empty_transaction(stellar_from, seq, memo)
    if amount > 0:
        stroops = int(amount * 10000000)
        if stroops <= 0:
            raise ValueError("Amount must be positive")
        tx = append_payment_op(tx, stellar_to, stroops)
    else:
        tx = append_set_options_op(tx)
    tx = sign_transaction(tx, stellar_from_secret)
    submit_transaction(tx)
    print(colors.GREEN + "Success!" + colors.END)
