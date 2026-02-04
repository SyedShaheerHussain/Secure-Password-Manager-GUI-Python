import secrets, string, hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ---------------- AES ENCRYPTION ----------------

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from a password and salt using PBKDF2-HMAC-SHA256.
    """
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

def encrypt_password(key: bytes, plaintext: str) -> tuple:
    """
    Encrypt a plaintext password using AES-256-CFB.
    Returns (iv, ciphertext)
    """
    key = key[:32]
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv, ct

def decrypt_password(key: bytes, iv: bytes, ct: bytes) -> str:
    """
    Decrypt AES-256-CFB encrypted password.
    """
    key = key[:32]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return (decryptor.update(ct) + decryptor.finalize()).decode()

# ---------------- PASSWORD GENERATOR ----------------
def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True) -> str:
    chars = ''
    if upper: chars += string.ascii_uppercase
    if lower: chars += string.ascii_lowercase
    if digits: chars += string.digits
    if symbols: chars += string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

# ---------------- PASSWORD STRENGTH ----------------
def password_strength(pwd: str) -> str:
    score = 0
    if any(c.islower() for c in pwd): score +=1
    if any(c.isupper() for c in pwd): score +=1
    if any(c.isdigit() for c in pwd): score +=1
    if any(c in "!@#$%^&*()-_=+[]{};:,.<>?/" for c in pwd): score +=1
    if len(pwd) >= 12: score +=1
    strengths = {0:"Very Weak",1:"Weak",2:"Medium",3:"Strong",4:"Very Strong",5:"Excellent"}
    return strengths.get(score, "Weak")

# ---------------- MD5 NAME FOR BACKUP ----------------
def md5_name(text: str) -> str:
    """Generate md5 hash from text for backup filename."""
    return hashlib.md5(text.encode()).hexdigest()
