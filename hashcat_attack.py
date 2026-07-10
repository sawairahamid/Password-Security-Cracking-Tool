import subprocess
import os
import shutil
import time
import json
import hashlib
import math

# ================== FILE PATHS ==================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_FILE = os.path.join(BASE_DIR, "hash.txt")
OUTPUT_FILE = os.path.join(BASE_DIR, "output.txt")
POTFILE = os.path.join(BASE_DIR, "hashcat.potfile")

# ================== WORDLISTS ==================
WORDLISTS = [
    os.path.join(BASE_DIR, "wordlist.txt"),   # local (safe)
    "/usr/share/wordlists/rockyou.txt",        # kali (read-only)
    "/usr/share/dict/words"
]

# ================== HASHCAT MODES ==================
HASH_TYPES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700
}

ATTACK_MODES = {
    "dictionary": 0,
    "bruteforce": 3,
    "combination": 1,
    "hybrid": 6
}

# ==================================================
def manual_dictionary_crack(hash_value, wordlist, hash_type="md5"):
    """
    Fallback: Manual dictionary attack if hashcat fails.
    This is slower but doesn't require GPU/memory.
    """
    print("[*] Using manual dictionary attack (fallback mode)")
    
    try:
        with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                password = line.strip()
                if not password:
                    continue
                
                # Hash the password and compare
                test_hash = hash_password(password, hash_type)
                
                if test_hash == hash_value:
                    print(f"[+] Match found at line {line_num}: {password}")
                    return password, "cracked"
                
                # Progress indicator every 1000 passwords
                if line_num % 1000 == 0:
                    print(f"[*] Tested {line_num} passwords...", end='\r')
        
        print(f"\n[*] Tested all passwords in wordlist")
        return None, "not cracked"
        
    except Exception as e:
        print(f"[!] Manual crack error: {str(e)}")
        return None, f"error: {str(e)}"

# ==================================================
def ensure_local_wordlist():
    """Create a small local wordlist if none exists"""
    wl = WORDLISTS[0]
    if not os.path.exists(wl):
        print(f"[*] Creating local wordlist at {wl}")
        with open(wl, "w") as f:
            # Common passwords for testing
            common_passwords = [
                "password", "123456", "admin", "welcome", "password123",
                "letmein", "qwerty", "abc123", "monkey", "dragon",
                "master", "sunshine", "princess", "football", "shadow"
            ]
            f.write("\n".join(common_passwords) + "\n")
        print(f"[+] Created wordlist with {len(common_passwords)} entries")

# ==================================================
def find_wordlist():
    """Find the first available and readable wordlist"""
    for w in WORDLISTS:
        if os.path.exists(w) and os.access(w, os.R_OK):
            print(f"[+] Using wordlist: {w}")
            return w
    print("[!] No readable wordlist found")
    return None

# ==================================================
def hash_password(password, hash_type="md5"):
    """Hash a password using the specified algorithm"""
    if hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        return hashlib.md5(password.encode()).hexdigest()

# ==================================================
def password_entropy(password):
    """Calculate the entropy of a password"""
    pool = 0
    if any(c.islower() for c in password): 
        pool += 26
    if any(c.isupper() for c in password): 
        pool += 26
    if any(c.isdigit() for c in password): 
        pool += 10
    if any(not c.isalnum() for c in password): 
        pool += 32
    
    if pool == 0:
        return 0
    
    return round(len(password) * math.log2(pool), 2)

# ==================================================
def run_hashcat(hash_value, hash_type="md5", timeout=30, use_fallback=True):
    """Run hashcat to crack a password hash"""
    if shutil.which("hashcat") is None:
        print("[!] Hashcat not installed, using manual mode")
        if use_fallback:
            wordlist = find_wordlist()
            if wordlist:
                return manual_dictionary_crack(hash_value, wordlist, hash_type)
        return None, "Hashcat not installed"
    
    wordlist = find_wordlist()
    if not wordlist:
        return None, "No readable wordlist found"
    
    # Write hash to file
    try:
        with open(HASH_FILE, "w") as f:
            f.write(hash_value + "\n")
    except Exception as e:
        return None, f"Error writing hash file: {str(e)}"
    
    # Remove old output files
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
    
    # Get hash mode
    hash_mode = HASH_TYPES.get(hash_type, 0)
    
    # Build hashcat command with optimizations for low memory
    cmd = [
        "hashcat",
        "-m", str(hash_mode),
        "-a", "0",  # Dictionary attack
        HASH_FILE,
        wordlist,
        "-o", OUTPUT_FILE,
        "--outfile-format", "3",  # hash:password format
        "--potfile-path", POTFILE,
        "--force",
        "--quiet",
        "-O",  # Optimized kernels (uses less memory)
        "-w", "1",  # Workload profile 1 (low)
        "--backend-ignore-opencl",  # Skip OpenCL if causing issues
        "--backend-ignore-cuda"  # Skip CUDA if causing issues
    ]
    
    print(f"[*] Running hashcat with mode {hash_mode} ({hash_type})")
    print(f"[*] Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Check for memory error
        if "Not enough allocatable device memory" in result.stderr:
            print("[!] Hashcat memory error detected")
            if use_fallback:
                print("[*] Switching to manual dictionary attack...")
                return manual_dictionary_crack(hash_value, wordlist, hash_type)
        
        if result.returncode != 0 and result.returncode != 1:
            print(f"[!] Hashcat error (code {result.returncode}): {result.stderr}")
            if use_fallback:
                print("[*] Switching to manual dictionary attack...")
                return manual_dictionary_crack(hash_value, wordlist, hash_type)
            
    except subprocess.TimeoutExpired:
        print(f"[!] Hashcat timeout after {timeout} seconds")
        if use_fallback:
            print("[*] Switching to manual dictionary attack...")
            return manual_dictionary_crack(hash_value, wordlist, hash_type)
        return None, "timeout"
    except Exception as e:
        print(f"[!] Error running hashcat: {str(e)}")
        if use_fallback:
            print("[*] Switching to manual dictionary attack...")
            return manual_dictionary_crack(hash_value, wordlist, hash_type)
        return None, str(e)
    
    # Check output file
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE) as f:
                content = f.read().strip()
                if content:
                    # Format: hash:password
                    parts = content.split(":", 1)
                    if len(parts) == 2:
                        print(f"[+] Password cracked: {parts[1]}")
                        return parts[1], "cracked"
        except Exception as e:
            print(f"[!] Error reading output file: {str(e)}")
    
    # Check potfile as fallback
    if os.path.exists(POTFILE):
        try:
            with open(POTFILE) as f:
                for line in f:
                    if hash_value in line:
                        parts = line.strip().split(":", 1)
                        if len(parts) == 2:
                            print(f"[+] Password found in potfile: {parts[1]}")
                            return parts[1], "cracked"
        except Exception as e:
            print(f"[!] Error reading potfile: {str(e)}")
    
    print("[!] Password not cracked")
    return None, "not cracked"

# ==================================================
def audit_password(password, hash_type="md5"):
    """
    Audit a password for strength and crackability.
    
    Workflow:
    1. Take plain text password
    2. Convert it to hash
    3. Attempt to crack the hash using hashcat
    4. Analyze results and strength
    """
    ensure_local_wordlist()
    
    print(f"\n{'='*60}")
    print("STEP 1: PASSWORD ANALYSIS")
    print(f"{'='*60}")
    print(f"[*] Original Password: {password}")
    print(f"[*] Password Length: {len(password)}")
    
    # Calculate entropy
    entropy = password_entropy(password)
    print(f"[*] Password Entropy: {entropy} bits")
    
    print(f"\n{'='*60}")
    print("STEP 2: CONVERTING PASSWORD TO HASH")
    print(f"{'='*60}")
    
    # Hash the password - THIS IS THE CONVERSION STEP
    hashed = hash_password(password, hash_type)
    print(f"[*] Hash Algorithm: {hash_type.upper()}")
    print(f"[*] Generated Hash: {hashed}")
    print(f"[*] Hash saved to: {HASH_FILE}")
    
    print(f"\n{'='*60}")
    print("STEP 3: ATTEMPTING TO CRACK THE HASH")
    print(f"{'='*60}")
    print(f"[*] Starting hashcat dictionary attack...")
    
    # Try to crack the hash
    start = time.time()
    cracked_pwd, status = run_hashcat(hashed, hash_type)
    elapsed = round(time.time() - start, 2)
    
    print(f"[*] Cracking completed in {elapsed} seconds")
    
    print(f"\n{'='*60}")
    print("STEP 4: RESULTS AND ANALYSIS")
    print(f"{'='*60}")
    
    # Build result
    result = {
        "original_password": password,
        "hash": hashed,
        "hash_type": hash_type,
        "entropy": entropy,
        "length": len(password),
        "time_to_crack": elapsed,
        "crack_status": status
    }
    
    if status == "cracked":
        print(f"[+] SUCCESS: Hash was cracked!")
        print(f"[+] Cracked Password: {cracked_pwd}")
        print(f"[!] VERDICT: WEAK PASSWORD - Found in wordlist in {elapsed}s")
        
        result["result"] = "WEAK PASSWORD - Found in wordlist"
        result["cracked_password"] = cracked_pwd
        result["strength"] = "WEAK"
        result["match"] = cracked_pwd == password
        
        if cracked_pwd == password:
            print(f"[+] Verification: Cracked password matches original ✓")
        else:
            print(f"[!] Warning: Cracked password does not match original")
            
    else:
        print(f"[-] Hash could not be cracked with current wordlist")
        
        # Estimate strength based on entropy
        if entropy < 28:
            print(f"[!] VERDICT: WEAK PASSWORD - Low entropy ({entropy} bits)")
            result["result"] = "WEAK PASSWORD - Low entropy but not in wordlist"
            result["strength"] = "WEAK"
        elif entropy < 50:
            print(f"[*] VERDICT: MODERATE PASSWORD - Medium entropy ({entropy} bits)")
            result["result"] = "MODERATE PASSWORD - Not found in wordlist"
            result["strength"] = "MODERATE"
        else:
            print(f"[+] VERDICT: STRONG PASSWORD - High entropy ({entropy} bits)")
            result["result"] = "STRONG PASSWORD - Not found in wordlist"
            result["strength"] = "STRONG"
    
    print(f"{'='*60}\n")
    
    return result

# ==================================================
def clean_temp_files():
    """Clean up temporary files"""
    files_to_clean = [HASH_FILE, OUTPUT_FILE, POTFILE]
    for f in files_to_clean:
        if os.path.exists(f):
            try:
                os.remove(f)
                print(f"[*] Cleaned up: {f}")
            except Exception as e:
                print(f"[!] Error cleaning {f}: {str(e)}")

# ==================================================
# MAIN FUNCTION FOR TESTING
# ==================================================
if __name__ == "__main__":
    print("="*50)
    print("PASSWORD ANALYZER & CRACKING TOOL")
    print("="*50)
    
    # Test passwords
    test_passwords = [
        "password",
        "MyStr0ngP@ss!",
        "admin123"
    ]
    
    for pwd in test_passwords:
        result = audit_password(pwd)
        print("\n" + "="*50)
        print("AUDIT RESULT:")
        print(json.dumps(result, indent=2))
        print("="*50)
    
    # Cleanup
    print("\n[*] Cleaning up temporary files...")
    clean_temp_files()
    print("\n[+] Done!")
