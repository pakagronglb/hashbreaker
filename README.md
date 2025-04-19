# HashBreaker - Advanced Password Cracker Tool

HashBreaker is a powerful yet user-friendly tool designed to crack hashed passwords. It supports various techniques including brute force, dictionary attacks, and rule-based attacks, providing a comprehensive solution for password recovery and security testing.


<img width="908" alt="Screenshot 2025-04-19 at 19 49 49" src="https://github.com/user-attachments/assets/d646d75a-f357-4867-a35a-8bdc3d90291b" />


## Table of Contents
- [Installation](#installation)
- [Getting Started](#getting-started)
- [Single Hash Cracking](#single-hash-cracking)
- [Batch Processing](#batch-processing)
- [Rainbow Tables](#rainbow-tables)
- [Hash Generator](#hash-generator)
- [Command Line Interface](#command-line-interface)
- [Converting to Electron](#converting-to-electron)
- [Ethical Usage](#ethical-usage)

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/pakagronglb/hashbreaker.git
   cd hashbreaker
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Getting Started

To run the application:

```
cd src
python3 main.py
```

The application interface consists of four main tabs:
- **Single Hash**: For cracking individual password hashes
- **Batch Processing**: For processing multiple hashes at once
- **Rainbow Tables**: For using precomputed hash chains for faster cracking
- **Hash Generator**: For creating hashes from passwords for testing

## Single Hash Cracking

This tab allows you to crack a single password hash using various methods.

### Hash Input Section

- **Hash Value**: Enter the hash you want to crack
- **Hash Type**: Select the hashing algorithm or use "Auto Detect" (identifies hash type based on length)
  - Supported types: MD5, SHA1, SHA256, SHA512

### Attack Methods

1. **Dictionary Attack**
   - Enable/disable using the checkbox
   - **Dictionary**: Path to a wordlist file containing common passwords
   - **Browse**: Select a dictionary file from your system
   
2. **Brute Force Attack**
   - Enable/disable using the checkbox
   - **Min Length** / **Max Length**: Set the range of password lengths to try
   - **Character Set**: Select which character types to include:
     - a-z (lowercase letters)
     - A-Z (uppercase letters)
     - 0-9 (digits)
     - !@#$... (special characters)

3. **Rule-Based Attack**
   - Enable/disable using the checkbox
   - **Base Words**: Enter common words separated by commas
   - The tool will apply transformations (capitalization, adding numbers, etc.)

### Progress Section

- **Progress Bar**: Shows the cracking progress
- **Status Text**: Displays messages and status updates
- **Result**: Shows the cracked password when found

### Control Buttons

- **Start Cracking**: Begins the password cracking process
- **Stop**: Cancels the current operation

### Usage Example

1. Enter a hash value (e.g., `5f4dcc3b5aa765d61d8327deb882cf99`)
2. Select hash type (or leave as "Auto Detect")
3. Configure attack methods:
   - Check "Dictionary Attack" and select a dictionary file
   - Check "Brute Force Attack" for shorter passwords (1-6 characters)
   - Add common words to "Rule-Based Attack" if you have hints about the password
4. Click "Start Cracking"
5. Monitor progress in the status area
6. Once found, the password will appear in the result field

## Batch Processing

This tab allows you to process multiple hashes simultaneously.

<img width="909" alt="Screenshot 2025-04-19 at 19 50 38" src="https://github.com/user-attachments/assets/b7567616-a23a-44b4-ac9a-a6ede408ace1" />


### Batch Hash Input

- **Input Area**: Enter one hash per line
- **Optional Format**: `label:hash` (e.g., `admin:5f4dcc3b5aa765d61d8327deb882cf99`)
- **Hash Type**: Select the type for all hashes or use "Auto Detect"

### File Operations

- **Load From File**: Import hashes from a text file
- **Save Results**: Export cracking results to a TXT or CSV file

### Attack Methods

Similar to Single Hash tab, configure:
- Dictionary Attack
- Brute Force Attack (lower max length recommended for better performance)

### Results Table

Displays four columns:
- **Label**: Name or identifier for each hash
- **Hash**: The hash value
- **Password**: The cracked password (if found)
- **Status**: Current state (Pending, Processing, Cracked, Not Found)

### Control Buttons

- **Start Batch Cracking**: Processes all hashes sequentially
- **Stop**: Cancels the batch operation

### Usage Example

1. Enter multiple hashes (one per line)
2. Optionally add labels with the format `label:hash`
3. Configure attack methods (prefer dictionary attack for batch processing)
4. Click "Start Batch Cracking"
5. Watch the Results table for progress
6. Save the results when complete

## Rainbow Tables

This tab provides an interface for using rainbow tables - precomputed lookup tables for reversing cryptographic hash functions.

### Rainbow Table Management

- **Table Directory**: Path to your rainbow tables folder
- **Browse**: Select a directory containing rainbow tables
- **Generate New Table**: Create a new rainbow table with specified parameters:
  - **Hash Type**: Algorithm (MD5, SHA1, SHA256)
  - **Min/Max Length**: Password length range
  - **Charset**: Character set to use (Lowercase, Lowercase+Digits, All)
  - **Generate**: Start the generation process (resource-intensive)

### Available Rainbow Tables

Displays a table of existing rainbow tables with:
- **Hash Type**: The hash algorithm
- **Charset**: The character set used
- **Length**: Password length range
- **Size**: File size of the table

<img width="909" alt="Screenshot 2025-04-19 at 19 51 43" src="https://github.com/user-attachments/assets/44afd5f0-9c9c-4284-a6df-9a057cf88a43" />


### Rainbow Table Lookup

- **Hash to Lookup**: Enter a hash to search in the tables
- **Lookup Hash**: Start the search process
- **Result**: Displays the found password or an empty field if not found

### Usage Example

1. Set the directory containing your rainbow tables
2. Refresh the table list to see available tables
3. Enter a hash value to lookup
4. Click "Lookup Hash"
5. Check the result field for the password (if found)

## Hash Generator

This tab allows you to create hashes from passwords and verify hash values.

### Generate Hash Section

- **Password**: Enter the password to hash
- **Hash Type**: Select the hashing algorithm from:
  - MD5
  - SHA1
  - SHA256
  - SHA512
  - Salted versions of the above
  - HMAC-SHA256
- **Salt**: Enter a salt value (for salted hash types) or use "Random"
- **Generate Hash**: Create the hash

<img width="909" alt="Screenshot 2025-04-19 at 19 52 11" src="https://github.com/user-attachments/assets/76c3e6b3-5500-4c27-8a4c-4f51bd3b7400" />


### Hash Output

Displays:
- **Hash Type**: The algorithm used
- **Password**: The input password
- **Salt**: The salt value (if used)
- **Hash Value**: The generated hash
- **Time Generated**: Timestamp

### Copy Hash to Clipboard

Copies the generated hash value to your clipboard.

### Verify Hash Section

- **Password**: Enter a password
- **Hash**: Enter a hash value
- **Hash Type**: Select the algorithm
- **Salt**: Enter a salt value (if applicable)
- **Verify**: Check if the password matches the hash
- **Result**: Shows "MATCH" or "NO MATCH"

### Usage Example

1. **To Generate a Hash**:
   - Enter a password
   - Select a hash type
   - Add a salt (if using a salted algorithm)
   - Click "Generate Hash"
   - The hash will appear in the output table

2. **To Verify a Hash**:
   - Enter the password and hash value
   - Select the correct hash type
   - Add the salt (if the hash used one)
   - Click "Verify"
   - Check the result indicator

## Command Line Interface

HashBreaker also offers a command-line interface for scripting and automation.

### Generating Hashes

```
python3 cli.py generate <password> [-t <hash_type>] [-s <salt>]
```

Examples:
```
# Generate an MD5 hash
python3 cli.py generate password123

# Generate a salted SHA256 hash
python3 cli.py generate mySecurePass -t sha256_salted -s mysalt
```

### Cracking Hashes

```
python3 cli.py crack <hash> [-t <hash_type>] [-d <dictionary>] [-b] [-r <words>] [-c <charset>] [-m <min_len>] [-x <max_len>]
```

Examples:
```
# Crack an MD5 hash using a dictionary
python3 cli.py crack 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -d wordlists/rockyou.txt

# Crack using brute force with custom charset and length
python3 cli.py crack 5f4dcc3b5aa765d61d8327deb882cf99 -b -c "abcdefgh12345" -m 3 -x 5

# Use rule-based attack with specific base words
python3 cli.py crack 5f4dcc3b5aa765d61d8327deb882cf99 -r "admin,password,user"
```

## Converting to Electron

HashBreaker can be converted into a cross-platform desktop application using Electron. See [docs/electron-conversion.md](docs/electron-conversion.md) for detailed instructions.

## Ethical Usage

HashBreaker is provided for educational purposes, security research, and legitimate password recovery. Users are responsible for ensuring they have proper authorization before attempting to crack password hashes in any environment.

Legitimate use cases include:
- Recovering your own forgotten passwords
- Testing password security policies
- Security education and training
- Authorized penetration testing

Never attempt to crack passwords you are not authorized to access.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
