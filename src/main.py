#!/usr/bin/env python3
"""
HashBreaker - Advanced Password Cracker Tool
This tool is designed to crack hashed passwords using various techniques
including brute force, dictionary attacks, and rule-based attacks.
"""

import sys
import os
from PyQt5.QtWidgets import QApplication
from gui import PasswordCrackerGUI  # Import the actual class

if __name__ == "__main__":
    # Create the data directory if it doesn't exist
    if not os.path.exists("data"):
        os.makedirs("data")
        
    # Create a default dictionary file if it doesn't exist
    default_dict = "data/common_passwords.txt"
    if not os.path.exists(default_dict):
        with open(default_dict, "w") as f:
            f.write("password\n123456\nadmin\nqwerty\nletmein\nwelcome\n"
                   "monkey\n111111\n12345678\ndragon\n1234567\nbaseball\n"
                   "football\n123456789\nstarwars\nprincess\nmaster\n"
                   "sunshine\nflower\nshadow\npassw0rd\ntrustno1\n"
                   "superman\nqazwsx\nmichael\nfootball1\n123123\n")
    
    # Start the GUI
    app = QApplication(sys.argv)
    window = PasswordCrackerGUI()
    window.show()
    sys.exit(app.exec_()) 