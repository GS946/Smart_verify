import re
import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
import jwt
from app.core.config import settings

# 1. File Encryption / Decryption via Fernet
# Ensure valid 32-byte urlsafe base64 key
_fernet_key = settings.ENCRYPTION_KEY.encode()
if len(_fernet_key) != 44:
    # Derive from secret key
    derived = base64.urlsafe_b64encode(hashlib.sha256(_fernet_key).digest())
    cipher_suite = Fernet(derived)
else:
    cipher_suite = Fernet(_fernet_key)

def encrypt_bytes(data: bytes) -> bytes:
    return cipher_suite.encrypt(data)

def decrypt_bytes(token: bytes) -> bytes:
    return cipher_suite.decrypt(token)

# 2. PII Masking
def mask_pii(text: str) -> str:
    if not text:
        return text
    # Mask Indian Aadhaar (12 digits)
    text = re.sub(r'\b\d{4}\s?\d{4}\s?(\d{4})\b', r'XXXX-XXXX-\1', text)
    # Mask Indian PAN (5 letters, 4 digits, 1 letter)
    text = re.sub(r'\b([A-Z]{5})\d{4}([A-Z])\b', r'\1****\2', text)
    # Mask Phone Numbers (10 digits)
    text = re.sub(r'\b(\+91[\-\s]?)?[6-9]\d{5}(\d{4})\b', r'+91-XXXXX-\2', text)
    # Mask Emails
    text = re.sub(r'\b([a-zA-Z0-9_.+-])[a-zA-Z0-9_.+-]+@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b', r'\1***@\2', text)
    return text

# 3. Secure PBKDF2-HMAC-SHA256 Password Hashing & JWT
def hash_password(password: str) -> str:
    salt = "aicte2026_salt_sec"
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000)
    return f"pbkdf2:{salt}:{dk.hex()}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not hashed_password:
        return False
    if hashed_password.startswith("pbkdf2:"):
        parts = hashed_password.split(":")
        if len(parts) == 3:
            _, salt, expected_hex = parts
            dk = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), 100000)
            return hmac.compare_digest(dk.hex(), expected_hex)
    # Legacy salted SHA-256 fallback
    if ":" in hashed_password:
        salt, h = hashed_password.split(":", 1)
        return hashlib.sha256((salt + plain_password).encode()).hexdigest() == h
    return plain_password == hashed_password

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_access_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except Exception:
        return None
