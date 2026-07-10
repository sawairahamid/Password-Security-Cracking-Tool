import os

def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Salts are used to prevent:
    - Rainbow table attacks
    - Hash reuse across identical passwords
    
    Default length: 16 bytes (128 bits)
    """
    return os.urandom(length)

def apply_salt(password: str, salt: bytes) -> bytes:
    """
    Apply salt to a password using concatenation.
    Order used: password + salt
    This must remain consistent during verification.
    
    NOTE:
    Salting alone does NOT slow down brute-force attacks.
    Key stretching algorithms like bcrypt or PBKDF2
    are recommended for secure password storage.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    
    return password.encode() + salt
