from . import core, application
import hashlib

HORIZON_URL = "https://horizon-testnet.stellar.org"
CHUNK_SIZE = 64
MAX_ENTRIES_PER_ACCOUNT = 500
MIME_FALLBACK = "application/octet-stream"
TESTNET_PASSPHRASE = "Test SDF Network ; September 2015"
NETWORK_ID = hashlib.sha256(TESTNET_PASSPHRASE.encode()).digest()

ENVELOPE_TYPE_TX         = b'\x00\x00\x00\x02'
PUBLIC_KEY_TYPE_ED25519  = b'\x00\x00\x00\x00'
SIGNATURE_HINT_LENGTH    = 4
VERSION_BYTE_ACCOUNT_ID = 6 << 3
VERSION_BYTE_SECRET_SEED = 18 << 3


__all__ = [
    "HORIZON_URL",
    "CHUNK_SIZE",
    "MAX_ENTRIES_PER_ACCOUNT",
    "MIME_FALLBACK",
    "TESTNET_PASSPHRASE",
    "NETWORK_ID",
    "ENVELOPE_TYPE_TX",        
    "PUBLIC_KEY_TYPE_ED25519", 
    "SIGNATURE_HINT_LENGTH",    
    "VERSION_BYTE_ACCOUNT_ID",
    "VERSION_BYTE_SECRET_SEED"
]
