
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

CONTENT_INDEXERS = {
    'html':    'fr0gey3nkjwxfi3olj2opkjwzxg2prjxwyld3rxthfuzqd5ssyzisbr3fcbg',
    'video':   'fr0gmypk54u3b5zytuzhwdbpxcyems234siebxa5wf2htz62smg4hbrtz5ag',
    'images':  'fr0gar7b4wscthfrqofckuq22clb3usofiud75gozxe26mqavyisrc5bemcg',
    'code':    'fr0g64n6okdmub2vqiiqmupwdtclsqakkbm3idbaz6c3kliddivpgfeetldg',
    'raw':     'fr0gcqkdfplmirjr5wxkez75mubdwow3i2ishskhgnesq4iyiishafeef2dg',
}


MIME_TO_CATEGORY = {
    # Websites / HTML
    'text/html': 'html',
    'application/xhtml+xml': 'html',

    # Video
    'video/mp4': 'video',
    'video/webm': 'video',
    'video/ogg': 'video',
    'video/quicktime': 'video',
    'video/x-matroska': 'video',

    # Images
    'image/jpeg': 'images',
    'image/png': 'images',
    'image/gif': 'images',
    'image/webp': 'images',
    'image/svg+xml': 'images',
    'image/bmp': 'images',
    'image/tiff': 'images',

    # Code / Text
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

TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"
HORIZON_URL = "https://horizon-testnet.stellar.org"
NETWORK_ID = hashlib.sha256(TESTNET_PASSPHRASE.encode()).digest()

ENVELOPE_TYPE_TX         = b'\x00\x00\x00\x02'
PUBLIC_KEY_TYPE_ED25519  = b'\x00\x00\x00\x00'
SIGNATURE_HINT_LENGTH    = 4
VERSION_BYTE_ACCOUNT_ID = 6 << 3
VERSION_BYTE_SECRET_SEED = 18 << 3

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
    #set_value(f':{fr0g_id}:',b'\x01', fr0g_secret)
    
    if airdrop_only==False:
       set_value(f':{fr0g_id}:',b'\x01', fr0g_secret)
    
def is_valid_identifier(s: str) -> bool:
    return s.isascii() and all(c.isdigit() or c.islower() or c == '_' for c in s)

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
              raise Exception('''Connection error: Fr0g ID was created but not initialized''')
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

def create_empty_transaction(source_account: str, sequence: int) -> Dict[str, Any]:
    tx = {
        "source_account": source_account,
        "sequence": sequence,
        "fee": 100,
        "time_bounds": None,
        "memo": {"type": "none"},
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

def append_create_account_op(
    tx: Dict[str, Any],
    destination: str,
    starting_balance: str = "1.0000000",
    memo_text: Optional[str] = None
) -> Dict[str, Any]:
    op = {
        "type": "create_account",
        "data": {
            "destination": destination,
            "starting_balance": starting_balance
        }
    }
    tx["operations"].append(op)
    if memo_text is not None:
        tx["memo"] = {"type": "text", "text": memo_text}
    return tx
'''
def append_payment_op(
    tx: Dict[str, Any],
    destination: str,
    amount: str = "1.0000000",
    memo_text: Optional[str] = None
) -> Dict[str, Any]:
    op = {
        "type": "payment",
        "data": {
            "destination": destination,
            "asset": {"type": "native"},
            "amount": amount
        }
    }
    tx["operations"].append(op)
    if memo_text is not None:
        tx["memo"] = {"type": "text", "text": memo_text}
    return tx
'''
def append_payment_op(
    tx: Dict[str, Any],
    destination: str,
    amount: str = "0.0000001",
    memo_text: str | None = None,
    memo_bytes: bytes | None = None
) -> Dict[str, Any]:
    """
    Aggiunge un'operazione payment con memo opzionale (text o bytes).

    Args:
        tx: transazione in costruzione
        destination: indirizzo Stellar destinatario (strkey)
        amount: importo in XLM (stringa decimale)
        memo_text: memo come stringa utf-8 (opzionale)
        memo_bytes: memo come byte raw (opzionale, ha priorità su memo_text)

    Returns:
        tx aggiornata
    """
    op = {
        "type": "payment",
        "data": {
            "destination": destination,
            "asset": {"type": "native"},
            "amount": amount
        }
    }
    tx["operations"].append(op)

    # Memo: priorità a bytes se fornito, altrimenti text
    if memo_bytes is not None:
        if len(memo_bytes) > 28:
            raise ValueError("Memo bytes exceeds Stellar limit of 28 bytes")
        tx["memo"] = {
            "type": "text",  # o "hash" / "return" se vuoi cambiare tipo
            "bytes": memo_bytes
        }
    elif memo_text is not None:
        memo_bytes = memo_text.encode("utf-8")
        if len(memo_bytes) > 28:
            raise ValueError(f"Memo text too long ({len(memo_bytes)} bytes > 28)")
        tx["memo"] = {
            "type": "text",
            "text": memo_text
        }
    # else: no memo

    return tx

def strkey_to_xdr_public_key(strkey: str) -> bytes:
    decoded = base64.b32decode(strkey)
    if len(decoded) != 35:
        raise ValueError(f"Invalid strkey length: {len(decoded)}")
    version = decoded[0]
    if version != VERSION_BYTE_ACCOUNT_ID:
        raise ValueError(f"Invalid version byte: {version}")
    payload = decoded[1:33]  
    return PUBLIC_KEY_TYPE_ED25519 + payload




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
    memo_xdr = struct.pack(">I", 0)
    time_bounds_xdr = struct.pack(">I", 0)
    ops_xdr = b""
    for op in tx["operations"]:
        op_source_xdr = struct.pack(">I", 0)
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
    tx_body_xdr = (
        source_account_xdr +
        fee_xdr +
        seq_num_xdr +
        memo_xdr +
        time_bounds_xdr +
        struct.pack(">I", len(tx["operations"])) +
        ops_xdr +
        struct.pack(">I", 0)
    )
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
    """
    Rimuove tutti i chunk e il next_f di un dato index su tutta la catena.
    """
    current_id = fr0g_id
    visited = set()
    removed = 0

    while current_id not in visited:
       
        visited.add(current_id)
       
        stellar_addr = fr0gID2stellar(current_id)

        # ─────────────────────────────────────────────────────────────
        # Aggiunta: controlliamo se l'account esiste prima di fare qualsiasi richiesta
        if not account_exists(stellar_addr):
            print(f"Account {stellar_addr} does not exist → assuming already cleared / never existed")
            # passiamo al prossimo (se esiste una catena) oppure usciamo
            # → dipende da come vuoi gestire la catena interrotta
            # Opzione conservativa: break
            #break
            # Opzione alternativa (più aggressiva): continue
            continue
        # ─────────────────────────────────────────────────────────────

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

        # Prosegui sulla catena (solo se c'era next_f per questo index)
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
def get_category(mime_type: str) -> str:
    """Determina la categoria dal MIME in modo più robusto"""
    if not mime_type:
        return 'raw'
    
    mime = mime_type.lower().split('+')[0].split(';')[0].strip()
    
    return MIME_CATEGORY_MAP.get(mime, 'raw')



def gzip_compress_if_useful(
    data: bytes,
    mime_type: str,
    min_savings_percent: float = 5.0,
    compression_level: int = 6
) -> Tuple[bytes, bool]:
    """
    Comprime i dati con gzip solo se il risparmio è significativo.

    Args:
        data: I dati originali in bytes
        mime_type: Tipo MIME del contenuto (usato per decidere se comprimere)
        min_savings_percent: Percentuale minima di risparmio per considerare utile la compressione
                             (default: 5.0 → almeno 5% più piccolo)
        compression_level: Livello di compressione gzip (1-9, default 6 = buon compromesso)

    Returns:
        Tuple[bytes, bool]:
            - bytes: dati compressi (o originali se non utile)
            - bool: True se è stata applicata la compressione gzip

    Esempi:
        >>> compressed, was_compressed = gzip_compress_if_useful(b"Hello world" * 1000, "text/plain")
        >>> was_compressed  # True se risparmio >5%
    """
    if not data:
        return b"", False

    # MIME che solitamente si comprimono bene
    compressible_prefixes = (
        'text/', 'application/json', 'application/javascript', 'application/xml',
        'application/xhtml+xml', 'image/svg+xml'
    )

    is_potentially_compressible = any(mime_type.lower().startswith(p) for p in compressible_prefixes)

    # Se non è un tipo comprimibile, restituiamo originale
    if not is_potentially_compressible:
        return data, False

    try:
        compressed = gzip.compress(data, compresslevel=compression_level)
        original_size = len(data)
        compressed_size = len(compressed)

        savings = (original_size - compressed_size) / original_size * 100 if original_size > 0 else 0

        if savings >= min_savings_percent:
            print(f"Gzip utile: {original_size:,} → {compressed_size:,} byte "
                  f"({savings:.1f}% savings)")
            return compressed, True
        else:
            print(f"Gzip non utile: risparmio solo {savings:.1f}% (< {min_savings_percent}%)")
            return data, False

    except Exception as e:
        print(f"Errore durante compressione gzip: {e}")
        return data, False
def append_payment_op(
    tx: dict,
    destination: str,
    amount: str = "0.0000001",
    memo_text: str | None = None,
    memo_bytes: bytes | None = None
) -> dict:
    """
    Appends a native XLM payment operation to the transaction.
    Supports optional memo (text or bytes). Memo bytes take priority if provided.

    Args:
        tx: Transaction dictionary (must have "operations" list)
        destination: Stellar account ID (G... strkey)
        amount: Amount in XLM as string (decimal)
        memo_text: Optional memo as UTF-8 string (max 28 bytes)
        memo_bytes: Optional memo as raw bytes (max 32 bytes for hash/return)

    Returns:
        Updated transaction dictionary
    """
    op = {
        "type": "payment",
        "data": {
            "destination": destination,
            "asset": {"type": "native"},
            "amount": amount
        }
    }
    tx["operations"].append(op)

    # Add memo if provided
    if memo_bytes is not None:
        if len(memo_bytes) > 32:
            raise ValueError("Memo bytes exceed 32 byte limit (for hash/return)")
        tx["memo"] = {"type": "hash", "hash": memo_bytes}
    elif memo_text is not None:
        memo_b = memo_text.encode("utf-8")
        if len(memo_b) > 28:
            raise ValueError(f"Memo text too long: {len(memo_b)} > 28 bytes")
        tx["memo"] = {"type": "text", "text": memo_text}

    return tx


def sign_payment_tx(tx: dict, secret_seed: str) -> dict:
    """
    Signs a transaction containing only payment operations (and optional memo).
    Handles XDR construction and base64 encoding correctly to avoid 'malformed' errors.

    Args:
        tx: Transaction dict with "source_account", "sequence", "fee", "operations", "memo" (optional)
        secret_seed: Secret key (S... strkey or 64-char HEX)

    Returns:
        Updated tx dict with "tx_xdr" and "tx_hash"
    """
    # Normalize secret seed
    secret_seed = secret_seed.upper().replace(" ", "").replace("-", "")
    
    # Decode secret
    if secret_seed.startswith("S"):
        padded = secret_seed + "=" * ((8 - len(secret_seed) % 8) % 8)
        raw = base64.b32decode(padded)
        if len(raw) != 35:
            raise ValueError("Invalid secret strkey")
        secret_bytes = raw[1:33]
    else:
        try:
            secret_bytes = bytes.fromhex(secret_seed)
            if len(secret_bytes) != 32:
                raise ValueError("Secret HEX must be 64 characters")
        except ValueError as e:
            raise ValueError(f"Invalid secret format: {e}")

    signing_key = SigningKey(secret_bytes)
    public_key_bytes = signing_key.get_verifying_key().to_bytes()

    # Source account XDR
    source_account_xdr = PUBLIC_KEY_TYPE_ED25519 + public_key_bytes

    # Fee (scaled by number of operations)
    fee_xdr = struct.pack(">I", tx["fee"] * len(tx["operations"]))

    # Sequence number
    seq_num_xdr = struct.pack(">Q", tx["sequence"])
    '''
    # Memo
    if "memo" in tx:
        memo = tx["memo"]
        if memo["type"] == "text":
            memo_b = memo["text"].encode("utf-8")
            pad_len = (4 - len(memo_b) % 4) % 4
            memo_xdr = (
                struct.pack(">I", 1) +  # MEMO_TEXT = 1
                struct.pack(">I", len(memo_b)) +
                memo_b +
                b"\x00" * pad_len
            )
        elif memo["type"] == "hash":
            memo_xdr = (
                struct.pack(">I", 2) +  # MEMO_HASH = 2
                memo["hash"]
            )
        else:
            raise ValueError(f"Unsupported memo type: {memo['type']}")
    else:
        memo_xdr = struct.pack(">I", 0)  # MEMO_NONE
    '''
    time_bounds_xdr = struct.pack(">I", 0)

    # Build operations XDR (only payment supported here)
    ops_xdr = b""
    for op in tx["operations"]:
        if op["type"] != "payment":
            raise ValueError(f"sign_payment_tx only supports payment ops, got {op['type']}")

        op_source_xdr = struct.pack(">I", 0)  # no source override

        dest_xdr = strkey_to_xdr_public_key(op["data"]["destination"])
        asset_xdr = struct.pack(">I", 0)  # native
        amount_stroops = int(float(op["data"]["amount"]) * 10_000_000)
        amount_xdr = struct.pack(">q", amount_stroops)

        op_body_xdr = dest_xdr + asset_xdr + amount_xdr
        op_type_code = 1  # PAYMENT

        ops_xdr += (
            op_source_xdr +
            struct.pack(">I", op_type_code) +
            op_body_xdr
        )

    # Transaction body XDR
    tx_body_xdr = (
        source_account_xdr +
        fee_xdr +
        seq_num_xdr +
        #memo_xdr+
        time_bounds_xdr +
        struct.pack(">I", len(tx["operations"])) +
        ops_xdr +
        struct.pack(">I", 0)  # no extension
    )

    # Payload to sign
    payload = NETWORK_ID + ENVELOPE_TYPE_TX + tx_body_xdr
    tx_hash = hashlib.sha256(payload).digest()

    # Signature
    signature = signing_key.sign(tx_hash)
    hint = public_key_bytes[-SIGNATURE_HINT_LENGTH:]

    # Envelope XDR
    envelope_xdr = (
        tx_body_xdr +
        struct.pack(">I", 1) +  # 1 signature
        hint +
        struct.pack(">I", len(signature)) +
        signature
    )

    # Base64 encode with proper padding
    encoded = base64.b64encode(envelope_xdr)
    tx["tx_xdr"] = encoded.decode("ascii")
    tx["tx_hash"] = tx_hash.hex()

    return tx

def account_exists(address: str) -> bool:
    """
    Checks if a Stellar account exists on Horizon.
    
    Args:
        address: Stellar public key (G... strkey)
    
    Returns:
        bool: True if account exists, False otherwise
    """
    try:
        url = f"{HORIZON_URL}/accounts/{address}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
        else:
            print(f"Unexpected status code checking account {address}: {response.status_code}")
            return False
    except Exception as e:
        print(f"Error checking account existence {address}: {str(e)}")
        return False

def upload(inp: bytes, fr0g_secret: str, index: int | str = 0, make_discoverable: bool = True) -> List[str]:
    if not inp:
        raise ValueError("Empty content")

    mime_type = guess_mime_type(inp)
    print(f"Type: {mime_type}")

    current_secret = fr0g_secret
    stellar_pub, _ = keypair_from_seed(bytes.fromhex(current_secret))
    current_id = stellar2fr0gID(stellar_pub)
    stellar_addr = fr0gID2stellar(current_id)

    if not account_exists(stellar_addr):
        print(f"Root account {stellar_addr} ({current_id}) does not exist → funding...")
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
        print(f"Auto-index: using next → #{target_index}")
    elif isinstance(index, int) and index >= 0:
        target_index = index
        print(f"Using specified index → #{target_index}")
    else:
        raise ValueError("index must be int >= 0 or 'next'")

    compressed_data, was_compressed = gzip_compress_if_useful(inp, mime_type)
    if was_compressed:
        print(f"Gzip compressed: {len(inp)} → {len(compressed_data)} bytes ({(len(inp)-len(compressed_data))/len(inp)*100:.1f}% savings)")
        data_to_upload = compressed_data
        mime_type += "+gzip"
    else:
        data_to_upload = inp

    chunks = chunk(data_to_upload)
    total_chunks = len(chunks)
    if total_chunks == 0:
        print("No chunks to upload (empty after padding?)")
        return all_ids

    chunk_idx = 0
    chunk_num = 1

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

        print(f"Uploading up to {max_chunks_this_account} chunks to {current_id} (slots available: {available_slots})")

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
                    print(f"Upload progress: {progress:.2f}% - {chunk_idx}/{total_chunks} chunks - account {current_id} - file #{target_index}")

            except Exception as e:
                print(f"Error during upload to {current_id}: {e}")
                raise
    print(f"Upload completed. Total accounts used: {len(all_ids)}")

    return all_ids




def get_mime_type(fr0g_id: str, file_index: int = 0) -> Optional[str]:
    """
    Ritorna il MIME type del file all'index specificato, seguendo la catena.
    """
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

            # Nuovo parsing: dopo "c" c'è chunk_num:mime
            try:
                rest = key.split("c", 1)[1]
                subparts = rest.split(":", 1)  # solo una volta
                if len(subparts) < 2:
                    continue

                chunk_num_str = subparts[0]
                mime_candidate = subparts[1].strip()

                # Verifica che chunk_num sia valido
                if chunk_num_str.isdigit():
                    if mime_candidate:
                        return mime_candidate
            except (IndexError, ValueError):
                continue

        # Segue next se esiste
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
    """
    Ricompone il contenuto completo per l'index specificato, seguendo la catena.
    """
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
                subparts = rest.split(":", 1)  # chunk_num : mime
                if len(subparts) < 1:
                    continue

                chunk_num_str = subparts[0]
                if not chunk_num_str.isdigit():
                    continue
                chunk_num = int(chunk_num_str)

                collected_chunks.append((chunk_num, value))

                # Prende MIME dal primo chunk che lo ha
                if mime_type is None and len(subparts) >= 2:
                    mime_type = subparts[1].strip()
            except (IndexError, ValueError):
                continue

        # Segue next
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

def get_minimum_balance(account_id):
    try:
        resp = requests.get(f"{HORIZON_URL}/accounts/{account_id}", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        return float(data.get("min_balance"))
    except Exception:
        return None

def get_xlm_balance(account_id):
    try:
        resp = requests.get(f"{HORIZON_URL}/accounts/{account_id}", timeout=10)
        resp.raise_for_status()
        data = resp.json()
        for bal in data.get("balances", []):
            if bal.get("asset_type") == "native":
                return float(bal.get("balance"))
        return None
    except Exception:
        return None

def is_horizon_reachable(horizon_url: str, timeout=3) -> bool:
    try:
        resp = requests.get(f"{HORIZON_URL}/", timeout=timeout)
        return resp.status_code == 200
    except Exception:
        return False

def get_first_manage_data_after_activation(account_id):
    fr0g_id = stellar2fr0gID(account_id)
    try:
        key = None
        value = None
        tx_resp = requests.get(f"{HORIZON_URL}/accounts/{account_id}/transactions", params={"order": "asc", "limit": 2}, timeout=10)
        tx_resp.raise_for_status()
        transactions = tx_resp.json().get("_embedded", {}).get("records", [])
        condition_1 = len(transactions) >= 2
        if condition_1:
            ops_resp = requests.get(f"{HORIZON_URL}/transactions/{transactions[1]['hash']}/operations", timeout=10)
            ops_resp.raise_for_status()
            operations = ops_resp.json().get("_embedded", {}).get("records", [])
            condition_2 = len(operations) == 1
            if condition_2:
                op = operations[0]
                condition_3 = op.get("type") == "manage_data"
                condition_4 = op.get("name") == f":{fr0g_id}:"
                value = op.get("value")
                condition_5 = (value is None) or (value == "AQ==")
                if condition_3 and condition_4 and condition_5:
                    key = op.get("name")
        if condition_1 and condition_2 and condition_3 and condition_4 and condition_5:
            return (key, value)
        return None
    except Exception:
        return None




def is_ID_legit(fr0g_id):
    data=get_first_manage_data_after_activation(fr0gID2stellar(fr0g_id))
    if data != None:
            if data[0]==f":{fr0g_id}:":
               return True
    return False

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
        print(f"Detected XLM price: ${xlm_usd:.6f}")
    except Exception as e:
        print(f"Error fetching XLM price: {e}")
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
    print(f"  → Estimated network fee:       {fee_per_byte:.2f} stroops/byte")
    print(f"  → Amortized reserve:   {reserve_stroops_per_byte:.2f} stroops/byte")
    print(f"  → Estimated total:         {total_stroops_per_byte:.2f} stroops/byte")
    return round(total_stroops_per_byte, 2)


def remaining_space(fr0g_id: str) -> int:
    from collections import deque
    visited = set()
    queue = deque([fr0g_id])
    all_accounts = set()
    remaining_slots_total = 0
    MAX_ENTRIES_PER_ACCOUNT = 500
    CHUNK_SIZE = 64
    MAX_TOTAL_ACCOUNTS = 8001  # 1 + 8000 child

    while queue:
        current = queue.popleft()
        if current in visited:
            continue
        visited.add(current)
        all_accounts.add(current)
        
        data_entries = retrieve_data(current)
        used_slots = 0
        
        # Conta solo le entry che "occupano spazio utile" per upload
        for key, _ in data_entries:
            if key.startswith("fr0g:f") or key.startswith("fr0g:next_f"):
                used_slots += 1
            # Opzionale: ignora anche ":fr0g_id:" se vuoi essere aggressivo
            # elif key == f":{current}:":
            #     pass  # non conta come "usato" per chunk

        remaining_in_this = max(0, MAX_ENTRIES_PER_ACCOUNT - used_slots)
        remaining_slots_total += remaining_in_this
        
        # Coda per next
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
    
    # Sort obbligatorio per numero chunk
    chunks.sort(key=lambda x: x[0])
    
    # Unisci tutti i chunk
    full = b''.join(val for _, val in chunks)
    
    # RIMUOVI SOLO PADDING FINALE \xff
    # Trova l'ultimo byte non-\xff dalla fine
    while full and full[-1] == 0xFF:
        full = full[:-1]
    
    mime = get_mime_type(id) or "application/octet-stream"
    is_gzipped = "+gzip" in mime
    mime_clean = mime.replace("+gzip", "")
    
    if is_gzipped:
        try:
            full = gzip.decompress(full)
        except Exception as e:
            print(f"Gzip decompress failed: {e}")
            return None, None
    
    return full, mime_clean







