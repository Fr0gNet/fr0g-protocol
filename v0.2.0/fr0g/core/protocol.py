import base64
import hashlib
from typing import List

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

from fr0g.ed25519_ext import SigningKey
import base64
import requests
import struct
import secrets
from typing import Dict, Any, List, Tuple, Optional
import hashlib



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



def is_valid_identifier(s: str) -> bool:
    return s.isascii() and all(c.isdigit() or c.islower() or c == '_' for c in s)

def stellar2fr0gID(stellar_address):
    return 'fr0g' + stellar_address.lower()[::-1]

def fr0gID2stellar(fr0g_id):
    return fr0g_id[4:][::-1].upper()

def fr0gsecret2stellar(fr0g_secret):
    return strkey_encode(VERSION_BYTE_SECRET_SEED, bytes.fromhex(fr0g_secret))

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



def strkey_to_xdr_public_key(strkey: str) -> bytes:
    decoded = base64.b32decode(strkey)
    if len(decoded) != 35:
        raise ValueError(f"Invalid strkey length: {len(decoded)}")
    version = decoded[0]
    if version != VERSION_BYTE_ACCOUNT_ID:
        raise ValueError(f"Invalid version byte: {version}")
    payload = decoded[1:33]  
    return PUBLIC_KEY_TYPE_ED25519 + payload


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
    if header.startswith(b'<!DOCTYPE html'):
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

def is_ID_legit(fr0g_id):
    data=get_first_manage_data_after_activation(fr0gID2stellar(fr0g_id))
    if data != None:
            if data[0]==f":{fr0g_id}:":
               return True
    return False

