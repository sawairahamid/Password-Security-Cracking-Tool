import hashlib
import bcrypt
from typing import Tuple
from salting import generate_salt, apply_salt

# =================================================
# BASIC HASHING (INSECURE – FOR DEMONSTRATION ONLY)
# =================================================
def md5_hash(password: str) -> str:
    """
    Generate MD5 hash.
    NOTE: MD5 is cryptographically broken and should NOT be used
    for password storage. Included only for educational comparison.
    """
    return hashlib.md5(password.encode()).hexdigest()

def sha1_hash(password: str) -> str:
    """
    Generate SHA-1 hash.
    NOTE: SHA-1 is deprecated due to collision attacks.
    Included for historical and comparison purposes only.
    """
    return hashlib.sha1(password.encode()).hexdigest()

# =================================================
# SECURE HASHING
# =================================================
def sha256_hash(password: str) -> str:
    """
    Generate SHA-256 hash.
    Secure for integrity checks, but NOT ideal alone for password storage
    without salting and key stretching.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def salted_sha256(password: str) -> Tuple[str, str]:
    """
    Generate SHA-256 hash with a random salt.
    Returns:
        (salt, hashed_password)
    """
    salt = generate_salt()
    salted_password = apply_salt(password, salt)
    # Ensure salted_password is bytes before hashing
    if isinstance(salted_password, str):
        salted_password = salted_password.encode()
    hashed = hashlib.sha256(salted_password).hexdigest()
    return salt, hashed

def verify_salted_sha256(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored salted SHA-256 hash.
    """
    salted_password = apply_salt(password, salt)
    if isinstance(salted_password, str):
        salted_password = salted_password.encode()
    computed_hash = hashlib.sha256(salted_password).hexdigest()
    return computed_hash == stored_hash

# =================================================
# BCRYPT (RECOMMENDED FOR PASSWORD STORAGE)
# =================================================
def bcrypt_hash(password: str, cost: int = 12) -> str:
    """
    Generate bcrypt hash.
    Bcrypt automatically applies salting and key stretching.
    Cost factor controls computational difficulty.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost))
    return hashed.decode()

def bcrypt_verify(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.
    """
    return bcrypt.checkpw(password.encode(), hashed.encode())
