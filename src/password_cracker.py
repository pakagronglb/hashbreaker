import hashlib
import itertools
import string
import time
from typing import List, Optional, Tuple

class PasswordCracker:
    """
    A class that provides methods to crack password hashes using various techniques
    """
    
    def __init__(self):
        self.common_hash_types = ["md5", "sha1", "sha256", "sha512"]
        
    def detect_hash_type(self, hash_value: str) -> str:
        """
        Attempt to detect the hash type based on length and structure
        """
        hash_length = len(hash_value)
        
        if hash_length == 32:
            return "md5"
        elif hash_length == 40:
            return "sha1"
        elif hash_length == 64:
            return "sha256"
        elif hash_length == 128:
            return "sha512"
        else:
            return "unknown"
    
    def hash_password(self, password: str, hash_type: str) -> str:
        """
        Hash a password using the specified algorithm
        """
        if hash_type == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type == "sha512":
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
    
    def brute_force(self, hash_value: str, hash_type: str, 
                   char_set: str = string.ascii_lowercase + string.digits,
                   min_length: int = 1, max_length: int = 8,
                   callback=None) -> Optional[str]:
        """
        Attempt to crack a hash using brute force
        """
        start_time = time.time()
        total_attempts = 0
        
        for length in range(min_length, max_length + 1):
            for attempt in itertools.product(char_set, repeat=length):
                password = ''.join(attempt)
                total_attempts += 1
                
                if total_attempts % 10000 == 0 and callback:
                    elapsed = time.time() - start_time
                    callback(password, total_attempts, elapsed)
                
                hashed = self.hash_password(password, hash_type)
                if hashed == hash_value:
                    if callback:
                        elapsed = time.time() - start_time
                        callback(password, total_attempts, elapsed, found=True)
                    return password
        
        return None
    
    def dictionary_attack(self, hash_value: str, hash_type: str, 
                         dictionary_path: str, callback=None) -> Optional[str]:
        """
        Attempt to crack a hash using a dictionary
        """
        start_time = time.time()
        total_attempts = 0
        
        try:
            with open(dictionary_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    password = line.strip()
                    total_attempts += 1
                    
                    if total_attempts % 1000 == 0 and callback:
                        elapsed = time.time() - start_time
                        callback(password, total_attempts, elapsed)
                    
                    hashed = self.hash_password(password, hash_type)
                    if hashed == hash_value:
                        if callback:
                            elapsed = time.time() - start_time
                            callback(password, total_attempts, elapsed, found=True)
                        return password
        except Exception as e:
            print(f"Error reading dictionary file: {e}")
            
        return None
    
    def rule_based_attack(self, hash_value: str, hash_type: str, 
                         base_words: List[str], callback=None) -> Optional[str]:
        """
        Apply common password transformation rules to base words
        """
        start_time = time.time()
        total_attempts = 0
        
        # Common transformations
        common_suffixes = ["123", "1234", "!", "@", "#", "2023", "2024"]
        common_prefixes = ["", "The", "My"]
        transformations = [
            lambda s: s,  # No change
            lambda s: s.capitalize(),
            lambda s: s.upper(),
            lambda s: s[::-1],  # Reverse
            lambda s: s + s,  # Repeat
        ]
        
        for word in base_words:
            for transform in transformations:
                for prefix in common_prefixes:
                    for suffix in common_suffixes:
                        password = prefix + transform(word) + suffix
                        total_attempts += 1
                        
                        if total_attempts % 1000 == 0 and callback:
                            elapsed = time.time() - start_time
                            callback(password, total_attempts, elapsed)
                        
                        hashed = self.hash_password(password, hash_type)
                        if hashed == hash_value:
                            if callback:
                                elapsed = time.time() - start_time
                                callback(password, total_attempts, elapsed, found=True)
                            return password
        
        return None
    
    def crack_password(self, hash_value: str, hash_type: str = None, 
                      methods: List[Tuple[str, dict]] = None,
                      callback=None) -> dict:
        """
        Attempt to crack a password hash using multiple methods
        """
        result = {
            "success": False,
            "password": None,
            "method": None,
            "attempts": 0,
            "time_elapsed": 0
        }
        
        # Auto-detect hash type if not specified
        if hash_type is None:
            hash_type = self.detect_hash_type(hash_value)
        
        # Default methods if none specified
        if methods is None:
            methods = [
                ("dictionary", {"dictionary_path": "data/common_passwords.txt"}),
                ("brute_force", {"max_length": 6})
            ]
        
        start_time = time.time()
        
        for method_name, method_params in methods:
            if callback:
                callback(status=f"Trying {method_name} attack...")
                
            if method_name == "brute_force":
                password = self.brute_force(hash_value, hash_type, callback=callback, **method_params)
            elif method_name == "dictionary":
                password = self.dictionary_attack(hash_value, hash_type, callback=callback, **method_params)
            elif method_name == "rule_based":
                password = self.rule_based_attack(hash_value, hash_type, callback=callback, **method_params)
            else:
                continue
                
            if password:
                result["success"] = True
                result["password"] = password
                result["method"] = method_name
                result["time_elapsed"] = time.time() - start_time
                break
                
        result["attempts"] = 0  # This would be tracked by the callback
        result["time_elapsed"] = time.time() - start_time
        
        return result 