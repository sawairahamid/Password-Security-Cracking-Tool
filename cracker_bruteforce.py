import itertools
import string
import time
from hashing import md5_hash


def brute_force_attack(
    password: str,
    max_length: int = 4,
    use_lowercase: bool = True,
    use_digits: bool = True
):
    """
    Simulated brute-force password attack (educational use only).

    This function demonstrates the exponential complexity of brute-force
    attacks using a constrained character set and length limit.
    """

    target_hash = md5_hash(password)

    charset = ""
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_digits:
        charset += string.digits

    if not charset:
        return {
            "success": False,
            "error": "Character set is empty"
        }

    start_time = time.time()
    attempts = 0

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            guess = ''.join(combo)

            # Simulated delay for realism
            time.sleep(0.001)

            if md5_hash(guess) == target_hash:
                return {
                    "success": True,
                    "attack_type": "Brute Force Attack",
                    "hash_algorithm": "MD5",
                    "password": guess,
                    "attempts": attempts,
                    "time_seconds": round(time.time() - start_time, 2),
                    "max_length": max_length
                }

    return {
        "success": False,
        "attack_type": "Brute Force Attack",
        "hash_algorithm": "MD5",
        "attempts": attempts,
        "reason": "Maximum length limit reached"
    }
