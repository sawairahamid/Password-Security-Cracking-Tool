import re
from entropy import calculate_entropy

# Frequently observed weak password patterns
COMMON_PATTERNS = ["123", "abc", "password", "qwerty", "admin"]


def analyze_password(password, dictionary_words=None):
    issues = []
    score = 0

    # Load dictionary internally if not provided
    if dictionary_words is None:
        try:
            with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
                dictionary_words = [line.strip().lower() for line in f]
        except FileNotFoundError:
            dictionary_words = []

    # ---------------- LENGTH ----------------
    if len(password) < 8:
        issues.append("Password is too short (minimum 8 characters recommended)")
    elif len(password) >= 12:
        score += 2  # Stronger weight for longer passwords
    else:
        score += 1

    # ---------------- CHARACTER VARIETY ----------------
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("Missing uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("Missing lowercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        issues.append("Missing numeric digits")

    if re.search(r"[!@#$%^&*()\-_=+]", password):
        score += 1
    else:
        issues.append("Missing special characters")

    # ---------------- COMMON PATTERNS ----------------
    for pattern in COMMON_PATTERNS:
        if pattern in password.lower():
            issues.append(f"Contains commonly used pattern: '{pattern}'")
            score -= 1  # Penalize weak patterns

    # ---------------- DICTIONARY CHECK ----------------
    for word in dictionary_words:
        if len(word) > 3 and word in password.lower():
            issues.append("Password contains dictionary-based word")
            score -= 1
            break

    # ---------------- ENTROPY ----------------
    entropy = calculate_entropy(password)

    # ---------------- FINAL STRENGTH ----------------
    if entropy < 40 or score <= 2:
        strength = "Weak"
    elif entropy < 60 or score <= 4:
        strength = "Moderate"
    else:
        strength = "Strong"

    return strength, entropy, issues
