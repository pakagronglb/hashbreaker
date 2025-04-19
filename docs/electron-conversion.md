# Converting HashBreaker to an Electron Application

This guide provides step-by-step instructions for converting the Python-based HashBreaker tool into a cross-platform Electron desktop application.

## Prerequisites

- Node.js (v14+) and npm (v6+)
- Python 3.6+ (already installed for HashBreaker)
- Basic knowledge of JavaScript and Node.js

## Step 1: Set Up the Electron Project

1. Create a new directory for the Electron project:

```bash
mkdir hashbreaker-electron
cd hashbreaker-electron
```

2. Initialize a new Node.js project:

```bash
npm init -y
```

3. Install Electron and other required dependencies:

```bash
npm install electron electron-builder python-shell nodemon --save-dev
```

## Step 2: Create the Electron Application Structure

Create the following directory structure:

```
hashbreaker-electron/
│
├── src/                  # Electron main process code
│   ├── main.js           # Electron entry point
│   └── preload.js        # Preload script
│
├── renderer/             # Frontend UI
│   ├── index.html        # Main window HTML
│   ├── styles.css        # CSS styles
│   └── renderer.js       # Frontend JavaScript
│
├── python/               # Python backend (copy from HashBreaker)
│   ├── password_cracker.py
│   ├── gui.py (modified)
│   ├── utils/
│   └── data/
│
├── package.json          # Node.js package configuration
└── electron-builder.yml  # Electron builder configuration
```

## Step 3: Modify the Python Backend

1. Create a Python module that exposes an API for the Electron app:

```python
# python/api.py
import json
import sys
from password_cracker import PasswordCracker
from utils.hash_generator import HashGenerator

def handle_command(command, params):
    """
    Handle commands from the Electron frontend
    """
    if command == "detect_hash_type":
        return detect_hash_type(params)
    elif command == "crack_password":
        return crack_password(params)
    elif command == "generate_hash":
        return generate_hash(params)
    else:
        return {"error": f"Unknown command: {command}"}

def detect_hash_type(params):
    cracker = PasswordCracker()
    hash_value = params.get("hash_value", "")
    hash_type = cracker.detect_hash_type(hash_value)
    return {"hash_type": hash_type}

def crack_password(params):
    cracker = PasswordCracker()
    hash_value = params.get("hash_value", "")
    hash_type = params.get("hash_type")
    
    methods = []
    if params.get("use_dictionary", False):
        methods.append(("dictionary", {"dictionary_path": params.get("dictionary_path")}))
    
    if params.get("use_brute_force", False):
        methods.append((
            "brute_force", 
            {
                "char_set": params.get("char_set", "abcdefghijklmnopqrstuvwxyz0123456789"),
                "min_length": params.get("min_length", 1),
                "max_length": params.get("max_length", 6)
            }
        ))
        
    if params.get("use_rule_based", False):
        methods.append((
            "rule_based", 
            {
                "base_words": params.get("base_words", [])
            }
        ))
    
    # Create a callback that prints JSON to stdout
    def callback(password=None, attempts=None, elapsed=None, found=False, status=None):
        update = {
            "type": "progress",
            "password": password,
            "attempts": attempts,
            "elapsed": elapsed,
            "found": found,
            "status": status
        }
        print(json.dumps(update), flush=True)
    
    result = cracker.crack_password(hash_value, hash_type, methods, callback)
    return {"type": "result", **result}

def generate_hash(params):
    generator = HashGenerator()
    password = params.get("password", "")
    hash_type = params.get("hash_type", "md5")
    salt = params.get("salt")
    
    result = generator.generate_hash(password, hash_type, salt)
    return result

if __name__ == "__main__":
    # Read input from stdin
    data = json.loads(sys.stdin.read())
    command = data.get("command")
    params = data.get("params", {})
    
    # Process the command
    result = handle_command(command, params)
    
    # Send the result back as JSON
    print(json.dumps(result), flush=True)
```

## Step 4: Create the Electron Main Process

```javascript
// src/main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const { PythonShell } = require('python-shell');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  
  // Open DevTools if in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }
}

app.whenReady().then(() => {
  createWindow();
  
  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});

// Handle Python communication
ipcMain.handle('python-command', async (event, { command, params }) => {
  try {
    return new Promise((resolve, reject) => {
      const options = {
        mode: 'json',
        pythonPath: 'python3',
        pythonOptions: ['-u'],
        scriptPath: path.join(__dirname, '../python')
      };
      
      const pyshell = new PythonShell('api.py', options);
      
      // Send the command to Python
      pyshell.send({ command, params });
      
      // Handle progress updates
      pyshell.on('message', function (message) {
        if (message.type === 'progress') {
          // Forward progress to renderer
          mainWindow.webContents.send('python-progress', message);
        } else {
          // This is the final result
          resolve(message);
        }
      });
      
      // Handle errors
      pyshell.on('error', function (err) {
        reject(err);
      });
      
      // End the process
      pyshell.end(function (err, code, signal) {
        if (err) reject(err);
      });
    });
  } catch (error) {
    return { error: error.message };
  }
});
```

## Step 5: Create the Preload Script

```javascript
// src/preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  sendCommand: (command, params) => {
    return ipcRenderer.invoke('python-command', { command, params });
  },
  onProgress: (callback) => {
    ipcRenderer.on('python-progress', (event, data) => callback(data));
  }
});
```

## Step 6: Create the HTML Interface

```html
<!-- renderer/index.html -->
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>HashBreaker - Advanced Password Cracker</title>
  <link rel="stylesheet" href="styles.css">
</head>
<body>
  <div class="container">
    <header>
      <h1>HashBreaker</h1>
      <p>Advanced Password Cracker Tool</p>
    </header>
    
    <div class="tab-container">
      <div class="tabs">
        <button class="tab-btn active" data-tab="single">Single Hash</button>
        <button class="tab-btn" data-tab="batch">Batch Processing</button>
        <button class="tab-btn" data-tab="rainbow">Rainbow Tables</button>
        <button class="tab-btn" data-tab="generator">Hash Generator</button>
      </div>
      
      <div class="tab-content active" id="single-tab">
        <!-- Hash Input Section -->
        <div class="card">
          <div class="card-header">Hash Input</div>
          <div class="card-body">
            <div class="form-group">
              <label for="hash-input">Hash Value:</label>
              <input type="text" id="hash-input" placeholder="Enter the hash value to crack...">
            </div>
            <div class="form-group">
              <label for="hash-type">Hash Type:</label>
              <select id="hash-type">
                <option value="auto">Auto Detect</option>
                <option value="md5">MD5</option>
                <option value="sha1">SHA1</option>
                <option value="sha256">SHA256</option>
                <option value="sha512">SHA512</option>
              </select>
            </div>
          </div>
        </div>
        
        <!-- Attack Methods Section -->
        <div class="card">
          <div class="card-header">Attack Methods</div>
          <div class="card-body">
            <!-- Dictionary Attack -->
            <div class="attack-method">
              <div class="form-check">
                <input type="checkbox" id="dict-check" checked>
                <label for="dict-check">Dictionary Attack</label>
              </div>
              <div class="form-group">
                <label for="dict-path">Dictionary:</label>
                <div class="input-group">
                  <input type="text" id="dict-path" placeholder="Path to dictionary file...">
                  <button id="dict-browse">Browse</button>
                </div>
              </div>
            </div>
            
            <!-- Brute Force Attack -->
            <div class="attack-method">
              <div class="form-check">
                <input type="checkbox" id="brute-check" checked>
                <label for="brute-check">Brute Force Attack</label>
              </div>
              <div class="form-group">
                <div class="input-group">
                  <label for="min-len">Min Length:</label>
                  <input type="number" id="min-len" value="1" min="1" max="10">
                  <label for="max-len">Max Length:</label>
                  <input type="number" id="max-len" value="6" min="1" max="10">
                </div>
              </div>
              <div class="form-group">
                <label>Character Set:</label>
                <div class="checkbox-group">
                  <div class="form-check">
                    <input type="checkbox" id="lowercase-check" checked>
                    <label for="lowercase-check">a-z</label>
                  </div>
                  <div class="form-check">
                    <input type="checkbox" id="uppercase-check">
                    <label for="uppercase-check">A-Z</label>
                  </div>
                  <div class="form-check">
                    <input type="checkbox" id="digits-check" checked>
                    <label for="digits-check">0-9</label>
                  </div>
                  <div class="form-check">
                    <input type="checkbox" id="symbols-check">
                    <label for="symbols-check">!@#$...</label>
                  </div>
                </div>
              </div>
            </div>
            
            <!-- Rule-based Attack -->
            <div class="attack-method">
              <div class="form-check">
                <input type="checkbox" id="rule-check">
                <label for="rule-check">Rule-Based Attack</label>
              </div>
              <div class="form-group">
                <label for="base-words">Base Words:</label>
                <input type="text" id="base-words" placeholder="Enter common words separated by commas...">
              </div>
            </div>
          </div>
        </div>
        
        <!-- Progress Section -->
        <div class="card">
          <div class="card-header">Progress</div>
          <div class="card-body">
            <div class="progress">
              <div id="progress-bar" class="progress-bar" role="progressbar"></div>
            </div>
            <div class="status-container">
              <div id="status-text" class="status-text"></div>
            </div>
            <div class="form-group">
              <label for="result-text">Result:</label>
              <input type="text" id="result-text" readonly>
            </div>
          </div>
        </div>
        
        <!-- Control Buttons -->
        <div class="button-group">
          <button id="start-button" class="btn primary">Start Cracking</button>
          <button id="stop-button" class="btn danger" disabled>Stop</button>
        </div>
      </div>
      
      <!-- Other tabs would go here -->
      <div class="tab-content" id="batch-tab">
        <p>Batch processing functionality coming soon...</p>
      </div>
      
      <div class="tab-content" id="rainbow-tab">
        <p>Rainbow tables functionality coming soon...</p>
      </div>
      
      <div class="tab-content" id="generator-tab">
        <p>Hash generator functionality coming soon...</p>
      </div>
    </div>
  </div>
  
  <script src="renderer.js"></script>
</body>
</html>
```

## Step 7: Write the CSS Styles

Create a modern, professional-looking UI with CSS.

## Step 8: Add the Renderer JavaScript Logic

```javascript
// renderer/renderer.js
document.addEventListener('DOMContentLoaded', () => {
  // Tab switching logic
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.getAttribute('data-tab');
      
      // Update active tab button
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      
      // Show active tab content
      tabContents.forEach(content => {
        content.classList.remove('active');
        if (content.id === `${tabName}-tab`) {
          content.classList.add('active');
        }
      });
    });
  });
  
  // Get UI elements
  const hashInput = document.getElementById('hash-input');
  const hashType = document.getElementById('hash-type');
  const dictCheck = document.getElementById('dict-check');
  const dictPath = document.getElementById('dict-path');
  const bruteCheck = document.getElementById('brute-check');
  const minLen = document.getElementById('min-len');
  const maxLen = document.getElementById('max-len');
  const lowercaseCheck = document.getElementById('lowercase-check');
  const uppercaseCheck = document.getElementById('uppercase-check');
  const digitsCheck = document.getElementById('digits-check');
  const symbolsCheck = document.getElementById('symbols-check');
  const ruleCheck = document.getElementById('rule-check');
  const baseWords = document.getElementById('base-words');
  const progressBar = document.getElementById('progress-bar');
  const statusText = document.getElementById('status-text');
  const resultText = document.getElementById('result-text');
  const startButton = document.getElementById('start-button');
  const stopButton = document.getElementById('stop-button');
  
  // Dictionary browse button
  document.getElementById('dict-browse').addEventListener('click', () => {
    // Electron dialog to be implemented
    // For now, set a default path
    dictPath.value = 'python/data/common_passwords.txt';
  });
  
  // Handle progress updates from Python
  let attempts = 0;
  let startTime = 0;
  
  window.api.onProgress(data => {
    if (data.status) {
      logStatus(data.status);
    }
    
    if (data.attempts) {
      attempts = data.attempts;
      updateProgressBar();
    }
    
    if (data.found) {
      resultText.value = data.password;
      logStatus(`Password found: ${data.password}`);
    }
  });
  
  // Start button
  startButton.addEventListener('click', async () => {
    const hash = hashInput.value.trim();
    if (!hash) {
      logStatus('Error: Please enter a hash value.');
      return;
    }
    
    // Get hash type
    let type = hashType.value;
    if (type === 'auto') {
      type = null;
    }
    
    // Build methods array
    const methods = [];
    
    // Reset UI
    progressBar.style.width = '0%';
    statusText.innerHTML = '';
    resultText.value = '';
    attempts = 0;
    startTime = Date.now();
    
    // Update button states
    startButton.disabled = true;
    stopButton.disabled = false;
    
    // Start password cracking
    try {
      const params = {
        hash_value: hash,
        hash_type: type,
        use_dictionary: dictCheck.checked,
        dictionary_path: dictPath.value || 'python/data/common_passwords.txt',
        use_brute_force: bruteCheck.checked,
        min_length: parseInt(minLen.value),
        max_length: parseInt(maxLen.value),
        char_set: getCharset(),
        use_rule_based: ruleCheck.checked,
        base_words: baseWords.value ? baseWords.value.split(',').map(w => w.trim()) : []
      };
      
      logStatus(`Starting password cracking for hash: ${hash}`);
      
      const result = await window.api.sendCommand('crack_password', params);
      
      if (result.success) {
        resultText.value = result.password;
        logStatus(`Password cracking completed successfully in ${result.time_elapsed.toFixed(2)} seconds`);
      } else {
        logStatus('Password cracking completed. No match found.');
      }
    } catch (error) {
      logStatus(`Error: ${error.message}`);
    } finally {
      startButton.disabled = false;
      stopButton.disabled = true;
    }
  });
  
  // Stop button
  stopButton.addEventListener('click', () => {
    // Send stop command to Python (to be implemented)
    logStatus('Stopping password cracking...');
    startButton.disabled = false;
    stopButton.disabled = true;
  });
  
  // Helper functions
  function getCharset() {
    let charset = '';
    if (lowercaseCheck.checked) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (uppercaseCheck.checked) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (digitsCheck.checked) charset += '0123456789';
    if (symbolsCheck.checked) charset += '!@#$%^&*()-_=+[]{}|;:,.<>?/`~';
    return charset || 'abcdefghijklmnopqrstuvwxyz0123456789';
  }
  
  function updateProgressBar() {
    const elapsed = (Date.now() - startTime) / 1000;
    progressBar.textContent = `${attempts} attempts | Elapsed: ${elapsed.toFixed(1)}s`;
    progressBar.style.width = `${Math.min(attempts % 100, 99)}%`;
  }
  
  function logStatus(message) {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    logEntry.innerHTML = `[${timestamp}] ${message}`;
    statusText.appendChild(logEntry);
    statusText.scrollTop = statusText.scrollHeight;
  }
});
```

## Step 9: Configure Electron Builder

Create an `electron-builder.yml` file for packaging:

```yaml
appId: com.hashbreaker.app
productName: HashBreaker
copyright: Copyright © 2023 HashBreaker
directories:
  output: dist
  buildResources: resources
files:
  - from: .
    filter:
      - package.json
      - src/**/*
      - renderer/**/*
      - python/**/*
      - '!node_modules/**/*'
extraResources:
  - from: python
    to: python
    filter:
      - '**/*'
asar: true
mac:
  category: public.app-category.developer-tools
  target:
    - dmg
    - zip
win:
  target:
    - nsis
    - portable
linux:
  target:
    - AppImage
    - deb
    - rpm
  category: Development
```

## Step 10: Update package.json

Add scripts for development and building:

```json
{
  "scripts": {
    "start": "electron src/main.js",
    "dev": "NODE_ENV=development nodemon --exec electron src/main.js",
    "build": "electron-builder",
    "build:mac": "electron-builder --mac",
    "build:win": "electron-builder --win",
    "build:linux": "electron-builder --linux"
  }
}
```

## Step 11: Running and Testing

1. Start the development server:

```bash
npm run dev
```

2. Build for production:

```bash
npm run build
```

## Troubleshooting

- If you encounter issues with Python detection, ensure the Python path is correct in `main.js`
- For packaging issues, try running with verbose logging: `electron-builder --verbose`

## Notes

- For production use, consider bundling Python with your application using PyInstaller
- Add error handling for situations where Python may not be installed
- Implement IPC communication for progress updates during long-running operations 