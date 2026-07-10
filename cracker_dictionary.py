import time
from hashing import md5_hash


def dictionary_attack(target_hash: str, wordlist=None):
    """
    Simulated dictionary-based password attack (educational use only).

    Demonstrates how weak hashing algorithms (e.g., MD5) are vulnerable
    to dictionary attacks.

    Returns:
        dict with cracked password details, or None if unsuccessful.
    """

    start_time = time.time()
    attempts = 0

    # Load wordlist internally if not provided
    if wordlist is None:
        try:
            with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
                wordlist = f.readlines()
        except FileNotFoundError:
            return None

    for word in wordlist:
        word = word.strip()
        if not word:
            continue

        attempts += 1

        # Simulated delay for realism
        time.sleep(0.001)

        if md5_hash(word) == target_hash:
            return {
                "attack_type": "Dictionary Attack",
                "hash_algorithm": "MD5",
                "password": word,
                "attempts": attempts,
                "time_seconds": round(time.time() - start_time, 2)
            }

    return None
