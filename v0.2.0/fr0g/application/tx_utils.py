from fr0g import HORIZON_URL, CHUNK_SIZE, MAX_ENTRIES_PER_ACCOUNT, MIME_FALLBACK, TESTNET_PASSPHRASE, NETWORK_ID, ENVELOPE_TYPE_TX, PUBLIC_KEY_TYPE_ED25519, SIGNATURE_HINT_LENGTH, VERSION_BYTE_ACCOUNT_ID, VERSION_BYTE_SECRET_SEED
from fr0g.ed25519_ext import SigningKey
from fr0g.core.protocol import strkey_encode,stellar2fr0gID,fr0gID2stellar
import base64, requests, struct, secrets, hashlib
from typing import Dict, Any, List, Tuple, Optional


def keypair_from_seed(seed):
    sk = SigningKey(seed)
    vk_obj = sk.get_verifying_key()
    vk = vk_obj.to_bytes()
    secret = strkey_encode(VERSION_BYTE_SECRET_SEED, seed)
    public_key = strkey_encode(VERSION_BYTE_ACCOUNT_ID, vk)
    return public_key, secret

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
def get_sequence_number(account_id):
    r = requests.get(f"{HORIZON_URL}/accounts/{account_id}")
    seq = int(r.json()["sequence"]) if r.ok else 0
    return seq
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


def sign_payment_tx(
    source_account: str,         
    sequence: int,
    destination: str,            
    amount: str | float,          
    create_account_if_missing: bool = False, 
    starting_balance: str = "1.0000000",      
    fee: int = 100,             
    memo_text: str | None = None,
    secret_seed_hex: str = None 
) -> dict:
    if not secret_seed_hex:
        raise ValueError("secret_seed_hex is required")
    try:
        secret_seed_bytes = bytes.fromhex(secret_seed_hex)
        if len(secret_seed_bytes) != 32:
            raise ValueError("Secret Hex must be 64 char length (32 byte)")
    except ValueError as e:
        raise ValueError(f"Invalid secret hex: {e}")
    signing_key = SigningKey(secret_seed_bytes)
    public_key_bytes = signing_key.get_verifying_key().to_bytes()
    source_account_xdr = strkey_to_xdr_public_key(source_account)
    fee_xdr = struct.pack(">I", fee)
    seq_num_xdr = struct.pack(">Q", sequence)
    memo_xdr = struct.pack(">I", 0)
    time_bounds_xdr = struct.pack(">I", 0)
    op_source_xdr = struct.pack(">I", 0)  
    if create_account_if_missing:
        dest_xdr = strkey_to_xdr_public_key(destination)
        balance_stroops = int(float(starting_balance) * 10_000_000)
        balance_xdr = struct.pack(">q", balance_stroops)
        op_body_xdr = dest_xdr + balance_xdr
        op_type_code = 0
    else:
        dest_xdr = strkey_to_xdr_public_key(destination)
        asset_type_xdr = struct.pack(">I", 0)
        amount_stroops = int(float(amount) * 10_000_000)
        amount_xdr = struct.pack(">q", amount_stroops)
        op_body_xdr = dest_xdr + asset_type_xdr + amount_xdr
        op_type_code = 1
    ops_xdr = op_source_xdr + struct.pack(">I", op_type_code) + op_body_xdr
    tx_body_xdr = (
        source_account_xdr +
        fee_xdr +
        seq_num_xdr +
        memo_xdr +
        time_bounds_xdr +
        struct.pack(">I", 1) +          
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
    return {
        "tx_xdr": base64.b64encode(envelope_xdr).decode("ascii"),
        "tx_hash": tx_hash.hex()
    }


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

def sendXLM(amount: float, to_address: str, memo_text: str, from_secret: str):
    if amount <= 0:
        raise ValueError("Amount must be positive")
    stellar_pubkey,stellar_secret=keypair_from_seed(bytes.fromhex(from_secret))[0]  ,fr0gsecret2stellar(from_secret)
    source_account = stellar_pubkey
    r = requests.get(f"{HORIZON_URL}/accounts/{to_address}")
    exists = r.ok
    seq = get_sequence_number(source_account) + 1
    tx_data = sign_payment_tx(
        source_account=source_account,
        sequence=seq,
        destination=to_address,
        amount=amount,
        create_account_if_missing=not exists,
        starting_balance="1.0000000" if not exists else None,
        fee=100,
        memo_text=memo_text,
        secret_seed_hex=from_secret
    )
    submit_transaction(tx_data)
def account_exists(stellar_addr: str) -> bool:
    try:
        r = requests.get(f"{HORIZON_URL}/accounts/{stellar_addr}")
        return r.status_code == 200
    except:
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




