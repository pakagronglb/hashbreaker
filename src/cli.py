#!/usr/bin/env python3
"""
Command-line interface for the HashBreaker password cracker tool
"""

import sys
import os
import time
import argparse
from password_cracker import PasswordCracker
from utils.hash_generator import HashGenerator

def main():
    parser = argparse.ArgumentParser(description="HashBreaker - Advanced Password Cracker Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Crack command
    crack_parser = subparsers.add_parser("crack", help="Crack a password hash")
    crack_parser.add_argument("hash", help="The hash value to crack")
    crack_parser.add_argument("-t", "--type", help="Hash type (md5, sha1, sha256, sha512)")
    crack_parser.add_argument("-d", "--dictionary", help="Path to dictionary file")
    crack_parser.add_argument("-b", "--brute-force", action="store_true", help="Use brute force attack")
    crack_parser.add_argument("-r", "--rule-based", help="Comma-separated list of base words for rule-based attack")
    crack_parser.add_argument("-c", "--charset", default="abcdefghijklmnopqrstuvwxyz0123456789", 
                              help="Character set for brute force attack")
    crack_parser.add_argument("-m", "--min-length", type=int, default=1, 
                              help="Minimum password length for brute force")
    crack_parser.add_argument("-x", "--max-length", type=int, default=6, 
                              help="Maximum password length for brute force")
    
    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate a password hash")
    gen_parser.add_argument("password", help="The password to hash")
    gen_parser.add_argument("-t", "--type", default="md5", 
                           help="Hash type (md5, sha1, sha256, sha512, md5_salted, sha1_salted, sha256_salted, sha512_salted)")
    gen_parser.add_argument("-s", "--salt", help="Salt value for salted hashes")
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == "crack":
        return crack_password(args)
    elif args.command == "generate":
        return generate_hash(args)
    
    return 0

def crack_password(args):
    print(f"[*] Starting password cracking for hash: {args.hash}")
    
    cracker = PasswordCracker()
    hash_type = args.type
    
    if not hash_type:
        hash_type = cracker.detect_hash_type(args.hash)
        print(f"[*] Auto-detected hash type: {hash_type}")
    
    # Configure methods
    methods = []
    
    if args.dictionary:
        print(f"[*] Adding dictionary attack using: {args.dictionary}")
        methods.append(("dictionary", {"dictionary_path": args.dictionary}))
    
    if args.brute_force:
        print(f"[*] Adding brute force attack (length {args.min_length}-{args.max_length})")
        methods.append((
            "brute_force", 
            {
                "char_set": args.charset,
                "min_length": args.min_length,
                "max_length": args.max_length
            }
        ))
    
    if args.rule_based:
        base_words = [word.strip() for word in args.rule_based.split(",")]
        print(f"[*] Adding rule-based attack with {len(base_words)} base words")
        methods.append(("rule_based", {"base_words": base_words}))
    
    if not methods:
        # Default to dictionary attack if no method specified
        dict_path = "data/common_passwords.txt"
        if not os.path.exists(dict_path):
            print(f"[!] Default dictionary not found, creating {dict_path}")
            os.makedirs("data", exist_ok=True)
            with open(dict_path, "w") as f:
                f.write("password\n123456\nadmin\nqwerty\nletmein\n")
        
        print(f"[*] Using default dictionary attack: {dict_path}")
        methods.append(("dictionary", {"dictionary_path": dict_path}))
    
    start_time = time.time()
    last_update = 0
    attempts = 0
    
    def progress_callback(password=None, current_attempts=None, elapsed=None, found=False, status=None):
        nonlocal attempts, last_update
        
        if current_attempts:
            attempts = current_attempts
        
        # Limit updates to once per second to avoid console spam
        current_time = time.time()
        if current_time - last_update > 1 or found:
            if status:
                print(f"[*] {status}")
            elif current_attempts:
                elapsed = time.time() - start_time
                print(f"[*] {attempts} attempts | {elapsed:.2f} seconds | {attempts/elapsed:.2f} attempts/sec")
            
            last_update = current_time
    
    result = cracker.crack_password(args.hash, hash_type, methods, progress_callback)
    
    if result["success"]:
        print(f"\n[+] Password found: {result['password']}")
        print(f"[+] Method: {result['method']}")
        print(f"[+] Time elapsed: {result['time_elapsed']:.2f} seconds")
        return 0
    else:
        print(f"\n[-] Password not found after {attempts} attempts")
        print(f"[-] Time elapsed: {time.time() - start_time:.2f} seconds")
        return 1

def generate_hash(args):
    generator = HashGenerator()
    
    try:
        result = generator.generate_hash(args.password, args.type, args.salt)
        print(f"\n[+] Password: {result['password']}")
        print(f"[+] Hash type: {result['hash_type']}")
        if result['salt']:
            print(f"[+] Salt: {result['salt']}")
        print(f"[+] Hash: {result['hash_value']}")
        return 0
    except ValueError as e:
        print(f"[!] Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main()) 