import hashlib
import os
import base64
import hmac
import binascii
from typing import Dict, Optional, Tuple

class HashGenerator:
    """
    Utility class for generating various types of password hashes
    """
    
    @staticmethod
    def generate_hash(password: str, hash_type: str, salt: Optional[str] = None) -> Dict[str, str]:
        """
        Generate a hash of the given password using the specified algorithm
        
        Args:
            password: The password to hash
            hash_type: The hash algorithm to use (md5, sha1, sha256, sha512, bcrypt, etc.)
            salt: Optional salt value (will be randomly generated if not provided)
            
        Returns:
            A dictionary containing the hash and metadata
        """
        if not salt and hash_type not in ["md5", "sha1", "sha256", "sha512"]:
            # Generate a random salt for algorithms that need it
            salt = binascii.hexlify(os.urandom(8)).decode()
        
        result = {
            "password": password,
            "hash_type": hash_type,
            "salt": salt,
            "hash_value": None
        }
        
        password_bytes = password.encode('utf-8')
        
        if hash_type == "md5":
            result["hash_value"] = hashlib.md5(password_bytes).hexdigest()
        elif hash_type == "sha1":
            result["hash_value"] = hashlib.sha1(password_bytes).hexdigest()
        elif hash_type == "sha256":
            result["hash_value"] = hashlib.sha256(password_bytes).hexdigest()
        elif hash_type == "sha512":
            result["hash_value"] = hashlib.sha512(password_bytes).hexdigest()
        elif hash_type == "md5_salted" and salt:
            salted = password_bytes + salt.encode('utf-8')
            result["hash_value"] = hashlib.md5(salted).hexdigest()
        elif hash_type == "sha1_salted" and salt:
            salted = password_bytes + salt.encode('utf-8')
            result["hash_value"] = hashlib.sha1(salted).hexdigest()
        elif hash_type == "sha256_salted" and salt:
            salted = password_bytes + salt.encode('utf-8')
            result["hash_value"] = hashlib.sha256(salted).hexdigest()
        elif hash_type == "sha512_salted" and salt:
            salted = password_bytes + salt.encode('utf-8')
            result["hash_value"] = hashlib.sha512(salted).hexdigest()
        elif hash_type == "hmac_sha256" and salt:
            result["hash_value"] = hmac.new(
                salt.encode('utf-8'), 
                password_bytes, 
                hashlib.sha256
            ).hexdigest()
        else:
            raise ValueError(f"Unsupported hash type: {hash_type}")
            
        return result
    
    @staticmethod
    def verify_hash(password: str, hash_value: str, hash_type: str, salt: Optional[str] = None) -> bool:
        """
        Verify if a password matches a hash
        
        Args:
            password: The password to check
            hash_value: The hash value to compare against
            hash_type: The hash algorithm used
            salt: The salt value (if used)
            
        Returns:
            True if the password matches the hash, False otherwise
        """
        try:
            result = HashGenerator.generate_hash(password, hash_type, salt)
            return result["hash_value"] == hash_value
        except Exception:
            return False 