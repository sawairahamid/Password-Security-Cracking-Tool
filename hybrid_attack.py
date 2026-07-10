import time
import hashlib
from typing import Callable, Optional
from hashing import md5_hash, sha256_hash
from salting import apply_salt


class HybridAttack:
    """
    Enhanced hybrid attack supporting multiple hash types and patterns.
    Demonstrates common password construction patterns.
    """
    
    def __init__(self, wordlist_path: str = "wordlist.txt"):
        self.wordlist_path = wordlist_path
        self.attempts = 0
        self.start_time = None
        
    def load_wordlist(self):
        """Load wordlist from file"""
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line.strip() for line in f if line.strip()]
            return words
        except FileNotFoundError:
            return None
    
    def md5_hash_func(self, password: str) -> str:
        """Generate MD5 hash"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def sha256_hash_func(self, password: str) -> str:
        """Generate SHA-256 hash"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def salted_sha256_hash_func(self, password: str, salt_bytes: bytes) -> str:
        """Generate salted SHA-256 hash"""
        salted = apply_salt(password, salt_bytes)
        return hashlib.sha256(salted).hexdigest()
    
    def generate_patterns(self, word: str, max_suffix: int = 100):
        """
        Generate multiple password patterns from a base word.
        
        Patterns:
        1. word + number (password123)
        2. number + word (123password)
        3. word + special + number (password!23)
        4. capitalized variations (Password123)
        """
        patterns = []
        
        # Pattern 1: word + number
        for num in range(max_suffix):
            patterns.append(f"{word}{num}")
        
        # Pattern 2: number + word
        for num in range(max_suffix):
            patterns.append(f"{num}{word}")
        
        # Pattern 3: word + special + number
        for special in ['!', '@', '#', '$', '_']:
            for num in range(10):  # Limit to 0-9 for these
                patterns.append(f"{word}{special}{num}")
        
        # Pattern 4: Capitalized + number
        if word.islower():
            capitalized = word.capitalize()
            for num in range(max_suffix):
                patterns.append(f"{capitalized}{num}")
        
        # Pattern 5: All caps + number
        if word.islower():
            upper = word.upper()
            for num in range(20):  # Limit for uppercase
                patterns.append(f"{upper}{num}")
        
        return patterns
    
    def attack(self, target_hash: str, hash_type: str = "md5", 
               max_suffix: int = 100, salt_hex: Optional[str] = None,
               progress_callback: Optional[Callable] = None):
        """
        Perform hybrid attack with multiple patterns.
        
        Args:
            target_hash: The hash to crack
            hash_type: "md5", "sha256", or "sha256_salted"
            max_suffix: Maximum numeric suffix to try
            salt_hex: Salt in hex format (required for salted hashes)
            progress_callback: Function to call with progress updates
        
        Returns:
            Dictionary with attack results
        """
        self.start_time = time.time()
        self.attempts = 0
        
        # Load wordlist
        wordlist = self.load_wordlist()
        if wordlist is None:
            return {
                "success": False,
                "error": "Wordlist file not found",
                "attempts": 0,
                "time": 0
            }
        
        # Select hash function
        if hash_type == "md5":
            hash_func = self.md5_hash_func
        elif hash_type == "sha256":
            hash_func = self.sha256_hash_func
        elif hash_type == "sha256_salted":
            if not salt_hex:
                return {
                    "success": False,
                    "error": "Salt required for salted hash",
                    "attempts": 0,
                    "time": 0
                }
            salt_bytes = bytes.fromhex(salt_hex)
            hash_func = lambda pwd: self.salted_sha256_hash_func(pwd, salt_bytes)
        else:
            return {
                "success": False,
                "error": f"Unsupported hash type: {hash_type}",
                "attempts": 0,
                "time": 0
            }
        
        # Perform attack
        total_words = len(wordlist)
        
        for word_idx, word in enumerate(wordlist):
            if not word:
                continue
            
            # Generate all patterns for this word
            patterns = self.generate_patterns(word, max_suffix)
            
            for pattern in patterns:
                self.attempts += 1
                
                # Progress update every 1000 attempts
                if progress_callback and self.attempts % 1000 == 0:
                    elapsed = time.time() - self.start_time
                    speed = self.attempts / elapsed if elapsed > 0 else 0
                    progress_callback({
                        "attempts": self.attempts,
                        "current_word": word,
                        "current_pattern": pattern,
                        "elapsed": elapsed,
                        "speed": speed,
                        "progress_percent": (word_idx / total_words) * 100
                    })
                
                # Check if hash matches
                try:
                    if hash_func(pattern) == target_hash:
                        elapsed = time.time() - self.start_time
                        return {
                            "success": True,
                            "password": pattern,
                            "base_word": word,
                            "attempts": self.attempts,
                            "time": round(elapsed, 2),
                            "hash_type": hash_type,
                            "pattern_type": self._identify_pattern(word, pattern)
                        }
                except Exception as e:
                    continue
        
        # Password not found
        elapsed = time.time() - self.start_time
        return {
            "success": False,
            "password": None,
            "attempts": self.attempts,
            "time": round(elapsed, 2),
            "hash_type": hash_type,
            "wordlist_size": len(wordlist)
        }
    
    def _identify_pattern(self, base_word: str, cracked_password: str) -> str:
        """Identify which pattern was used"""
        if cracked_password.startswith(base_word):
            suffix = cracked_password[len(base_word):]
            if suffix.isdigit():
                return f"word+number ({base_word}+{suffix})"
            elif suffix and suffix[0] in '!@#$_' and suffix[1:].isdigit():
                return f"word+special+number ({base_word}+{suffix[0]}+{suffix[1:]})"
        elif cracked_password.endswith(base_word):
            prefix = cracked_password[:-len(base_word)]
            if prefix.isdigit():
                return f"number+word ({prefix}+{base_word})"
        elif cracked_password.lower() == base_word.lower():
            return "capitalization variant"
        return "unknown pattern"
    
    def format_output(self, result: dict) -> str:
        """Format attack results for display"""
        output = []
        output.append("🔄 Hybrid Attack Results:")
        output.append("═" * 60)
        
        if result.get("success"):
            output.append(f"\n🚨 STATUS: PASSWORD CRACKED!")
            output.append(f"─" * 60)
            output.append(f"\n📊 Attack Details:")
            output.append(f"  • Attack Type: Hybrid (Dictionary + Pattern Matching)")
            output.append(f"  • Hash Algorithm: {result['hash_type'].upper()}")
            output.append(f"  • Cracked Password: '{result['password']}'")
            output.append(f"  • Base Word: '{result['base_word']}'")
            output.append(f"  • Pattern Used: {result['pattern_type']}")
            output.append(f"\n⚙️ Performance Metrics:")
            output.append(f"  • Total Attempts: {result['attempts']:,}")
            output.append(f"  • Time Elapsed: {result['time']}s")
            output.append(f"  • Average Speed: {int(result['attempts']/result['time']):,} attempts/sec")
            output.append(f"\n⚠️ SECURITY ALERT:")
            output.append(f"  Your password follows a predictable pattern and was")
            output.append(f"  compromised using hybrid attack methods.")
            output.append(f"\n💡 Recommendations:")
            output.append(f"  • Avoid dictionary words with predictable modifications")
            output.append(f"  • Use random combinations of letters, numbers & symbols")
            output.append(f"  • Consider using a passphrase (4+ random words)")
            output.append(f"  • Use a password manager for complex passwords")
            
        else:
            output.append(f"\n✅ STATUS: Password Resistant")
            output.append(f"─" * 60)
            output.append(f"\n📊 Attack Details:")
            output.append(f"  • Attack Type: Hybrid (Dictionary + Pattern Matching)")
            output.append(f"  • Hash Algorithm: {result['hash_type'].upper()}")
            output.append(f"  • Result: No match found")
            output.append(f"\n⚙️ Performance Metrics:")
            output.append(f"  • Total Attempts: {result['attempts']:,}")
            output.append(f"  • Time Elapsed: {result['time']}s")
            if result['time'] > 0:
                output.append(f"  • Average Speed: {int(result['attempts']/result['time']):,} attempts/sec")
            output.append(f"  • Wordlist Size: {result.get('wordlist_size', 'N/A')} words")
            output.append(f"\n🛡️ SECURITY STATUS:")
            output.append(f"  Your password successfully resisted hybrid attack methods.")
            output.append(f"  It doesn't follow common dictionary+pattern combinations.")
            output.append(f"\n💡 Good Practices Detected:")
            output.append(f"  • Password is not a simple dictionary word variation")
            output.append(f"  • Shows resistance to common attack patterns")
            output.append(f"  • Demonstrates good password complexity")
        
        output.append(f"\n" + "═" * 60)
        return "\n".join(output)


def hybrid_attack(target_hash: str, max_suffix: int = 100, 
                 hash_type: str = "md5", salt_hex: Optional[str] = None):
    """
    Backwards-compatible function for existing code.
    Performs hybrid attack and returns formatted string.
    """
    attacker = HybridAttack()
    
    # Progress callback for console output
    def show_progress(progress):
        if progress["attempts"] % 5000 == 0:
            print(f"  Trying: {progress['current_pattern']:<20} "
                  f"[{progress['attempts']:,} attempts, "
                  f"{int(progress['speed']):,}/s]")
    
    print(f"\n🔄 Starting Hybrid Attack...")
    print(f"Hash Type: {hash_type.upper()}")
    print(f"Target: {target_hash}")
    if salt_hex:
        print(f"Salt: {salt_hex}")
    print(f"─" * 60)
    
    result = attacker.attack(
        target_hash, 
        hash_type=hash_type,
        max_suffix=max_suffix,
        salt_hex=salt_hex,
        progress_callback=show_progress
    )
    
    return attacker.format_output(result)


# Test function
if __name__ == "__main__":
    print("Testing Hybrid Attack Module\n")
    
    # Test 1: MD5
    test_password = "password123"
    test_hash = md5_hash(test_password)
    print(f"Test Password: {test_password}")
    print(f"MD5 Hash: {test_hash}\n")
    
    result = hybrid_attack(test_hash, max_suffix=200, hash_type="md5")
    print(result)
    
    # Test 2: SHA256
    print("\n" + "="*60)
    print("Testing SHA-256...")
    test_hash_sha256 = sha256_hash(test_password)
    print(f"SHA-256 Hash: {test_hash_sha256}\n")
    
    result2 = hybrid_attack(test_hash_sha256, max_suffix=200, hash_type="sha256")
    print(result2)
