import math


def calculate_entropy(password: str) -> float:
    """
    Calculates approximate Shannon entropy of a password.

    Entropy = L × log2(N)
    Where:
    L = length of password
    N = size of character set used

    Higher entropy implies higher resistance against brute-force attacks.
    """

    if not password:
        return 0.0

    # Detect unique character categories used
    categories = {
        "lowercase": set("abcdefghijklmnopqrstuvwxyz"),
        "uppercase": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "digits": set("0123456789"),
        "symbols": set("!@#$%^&*()-_=+[]{};:,.<>/?")
    }

    charset_size = 0

    for charset in categories.values():
        if any(char in charset for char in password):
            charset_size += len(charset)

    if charset_size == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_size)

    return round(entropy, 2)
