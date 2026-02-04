import bcrypt
import hashlib
import os

# ---------------- MASTER PASSWORD ----------------
def hash_password(password: str) -> bytes:
    """Hash a master or vault password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def verify_password(password: str, hashed: bytes) -> bool:
    """Verify a password against a bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.
    This key is used for encrypting/decrypting user passwords in the vault.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def generate_salt(length: int = 16) -> bytes:
    """Generate a cryptographic salt."""
    return os.urandom(length)
