import os
import base64
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from passlib.context import CryptContext
from jose import jwt, JWTError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_raw_key = os.getenv("AES_ENCRYPTION_KEY", "73617479617661737472615f7365637572655f6b65795f323032365f33326279")
try:
    AES_KEY = bytes.fromhex(_raw_key)
    if len(AES_KEY) != 32:
        raise ValueError()
except Exception:
    AES_KEY = hashlib.sha256(_raw_key.encode()).digest()

JWT_SECRET = os.getenv("SECRET_KEY", "satyavastra-secret-jwt-signing-key-2026-pmec")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

def encrypt_field(plain_text: str) -> str:
    if not plain_text:
        return ""
    if not isinstance(plain_text, str):
        plain_text = str(plain_text)
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    encoded = base64.b64encode(nonce + ciphertext).decode("utf-8")
    return "AES256GCM:" + encoded

def decrypt_field(encrypted_str: str) -> str:
    if not encrypted_str or not encrypted_str.startswith("AES256GCM:"):
        return encrypted_str or ""
    try:
        raw_b64 = encrypted_str.replace("AES256GCM:", "")
        raw_bytes = base64.b64decode(raw_b64.encode("utf-8"))
        nonce = raw_bytes[:12]
        ciphertext = raw_bytes[12:]
        aesgcm = AESGCM(AES_KEY)
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")
    except Exception as e:
        return f"[DECRYPTION_FAILED: {str(e)}]"

def encrypt_bytes(raw_bytes: bytes) -> bytes:
    aesgcm = AESGCM(AES_KEY)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
    return nonce + ciphertext

def decrypt_bytes(encrypted_bytes: bytes) -> bytes:
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    aesgcm = AESGCM(AES_KEY)
    return aesgcm.decrypt(nonce, ciphertext, None)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

def sign_qr_payload(serial: str, expires_at_ts: int) -> str:
    message = f"{serial}|{expires_at_ts}".encode()
    return hmac.new(AES_KEY, message, hashlib.sha256).hexdigest()[:16]

def verify_qr_signature(serial: str, expires_at_ts: int, signature: str) -> bool:
    expected = sign_qr_payload(serial, expires_at_ts)
    return hmac.compare_digest(expected, signature)

def compute_deterministic_code(serial: str, weaver_name: str, hours: int) -> str:
    raw = f"{serial}|{weaver_name}|{hours}|SV26"
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    h1 = 2166136261
    for char in raw:
        h1 = (h1 ^ ord(char)) * 16777619 & 0xFFFFFFFF
    h2 = (h1 ^ 0x9e3779b9) & 0xFFFFFFFF
    for char in raw:
        h2 = (h2 ^ ord(char)) * 16777619 & 0xFFFFFFFF
    part1 = "".join([alphabet[(h1 >> (i * 5)) & 31] for i in range(4)])
    part2 = "".join([alphabet[(h2 >> (i * 5)) & 31] for i in range(4)])
    return f"SV-{part1}-{part2}"
