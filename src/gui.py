import sys
import os
import time
import binascii
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QComboBox, QFileDialog, QProgressBar, QTextEdit,
                             QTabWidget, QSpinBox, QCheckBox, QGroupBox, QRadioButton,
                             QTableWidget, QTableWidgetItem, QHeaderView, QPlainTextEdit,
                             QSplitter, QFrame, QDialog, QMessageBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QTextCursor

# Import our password cracker
from password_cracker import PasswordCracker
from utils.hash_generator import HashGenerator

class CrackerThread(QThread):
    """
    Thread for running password cracking operations without freezing the UI
    """
    update_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal(dict)
    
    def __init__(self, cracker, hash_value, hash_type, methods):
        super().__init__()
        self.cracker = cracker
        self.hash_value = hash_value
        self.hash_type = hash_type
        self.methods = methods
        self.running = True
        
    def run(self):
        def callback(password=None, attempts=None, elapsed=None, found=False, status=None):
            if not self.running:
                return
                
            update = {
                "password": password,
                "attempts": attempts,
                "elapsed": elapsed,
                "found": found,
                "status": status
            }
            self.update_signal.emit(update)
        
        result = self.cracker.crack_password(
            self.hash_value, 
            self.hash_type, 
            self.methods,
            callback
        )
        
        if self.running:
            self.finished_signal.emit(result)
    
    def stop(self):
        self.running = False


class PasswordCrackerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cracker = PasswordCracker()
        self.hash_generator = HashGenerator()
        self.cracker_thread = None
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("HashBreaker - Advanced Password Cracker")
        self.setMinimumSize(800, 600)
        
        # Create main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Create tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Create first tab for single hash cracking
        single_tab = QWidget()
        single_layout = QVBoxLayout()
        single_tab.setLayout(single_layout)
        tabs.addTab(single_tab, "Single Hash")
        
        # Hash input section
        hash_group = QGroupBox("Hash Input")
        hash_layout = QVBoxLayout()
        hash_group.setLayout(hash_layout)
        
        hash_input_layout = QHBoxLayout()
        hash_label = QLabel("Hash Value:")
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Enter the hash value to crack...")
        hash_input_layout.addWidget(hash_label)
        hash_input_layout.addWidget(self.hash_input)
        hash_layout.addLayout(hash_input_layout)
        
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.hash_type_combo = QComboBox()
        self.hash_type_combo.addItems(["Auto Detect", "MD5", "SHA1", "SHA256", "SHA512"])
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.hash_type_combo)
        hash_layout.addLayout(hash_type_layout)
        
        single_layout.addWidget(hash_group)
        
        # Attack methods section
        methods_group = QGroupBox("Attack Methods")
        methods_layout = QVBoxLayout()
        methods_group.setLayout(methods_layout)
        
        # Dictionary attack options
        self.dict_check = QCheckBox("Dictionary Attack")
        self.dict_check.setChecked(True)
        dict_layout = QHBoxLayout()
        dict_path_label = QLabel("Dictionary:")
        self.dict_path = QLineEdit()
        self.dict_path.setPlaceholderText("Path to dictionary file...")
        dict_browse = QPushButton("Browse")
        dict_browse.clicked.connect(self.browse_dictionary)
        dict_layout.addWidget(dict_path_label)
        dict_layout.addWidget(self.dict_path)
        dict_layout.addWidget(dict_browse)
        
        methods_layout.addWidget(self.dict_check)
        methods_layout.addLayout(dict_layout)
        
        # Brute force options
        self.brute_check = QCheckBox("Brute Force Attack")
        self.brute_check.setChecked(True)
        brute_layout = QHBoxLayout()
        min_len_label = QLabel("Min Length:")
        self.min_len_spin = QSpinBox()
        self.min_len_spin.setValue(1)
        max_len_label = QLabel("Max Length:")
        self.max_len_spin = QSpinBox()
        self.max_len_spin.setValue(6)
        brute_layout.addWidget(min_len_label)
        brute_layout.addWidget(self.min_len_spin)
        brute_layout.addWidget(max_len_label)
        brute_layout.addWidget(self.max_len_spin)
        
        charset_layout = QHBoxLayout()
        charset_label = QLabel("Character Set:")
        self.lowercase_check = QCheckBox("a-z")
        self.lowercase_check.setChecked(True)
        self.uppercase_check = QCheckBox("A-Z")
        self.digits_check = QCheckBox("0-9")
        self.symbols_check = QCheckBox("!@#$...")
        charset_layout.addWidget(charset_label)
        charset_layout.addWidget(self.lowercase_check)
        charset_layout.addWidget(self.uppercase_check)
        charset_layout.addWidget(self.digits_check)
        charset_layout.addWidget(self.symbols_check)
        
        methods_layout.addWidget(self.brute_check)
        methods_layout.addLayout(brute_layout)
        methods_layout.addLayout(charset_layout)
        
        # Rule-based attack
        self.rule_check = QCheckBox("Rule-Based Attack")
        rule_layout = QHBoxLayout()
        words_label = QLabel("Base Words:")
        self.base_words = QLineEdit()
        self.base_words.setPlaceholderText("Enter common words separated by commas...")
        rule_layout.addWidget(words_label)
        rule_layout.addWidget(self.base_words)
        
        methods_layout.addWidget(self.rule_check)
        methods_layout.addLayout(rule_layout)
        
        single_layout.addWidget(methods_group)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        progress_group.setLayout(progress_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v attempts | %p% | Elapsed: %vs")
        self.progress_bar.setValue(0)
        
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(150)
        
        result_layout = QHBoxLayout()
        result_label = QLabel("Result:")
        self.result_text = QLineEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(result_label)
        result_layout.addWidget(self.result_text)
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_text)
        progress_layout.addLayout(result_layout)
        
        single_layout.addWidget(progress_group)
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Cracking")
        self.start_button.clicked.connect(self.start_cracking)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_cracking)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        
        single_layout.addLayout(button_layout)
        
        # Create second tab for batch processing
        batch_tab = QWidget()
        batch_layout = QVBoxLayout()
        batch_tab.setLayout(batch_layout)
        tabs.addTab(batch_tab, "Batch Processing")
        
        # Batch input section
        batch_input_group = QGroupBox("Batch Hash Input")
        batch_input_layout = QVBoxLayout()
        batch_input_group.setLayout(batch_input_layout)
        
        batch_input_help = QLabel("Enter one hash per line. Optionally, add a label followed by a colon.")
        batch_input_help.setWordWrap(True)
        batch_input_example = QLabel("Example: admin:5f4dcc3b5aa765d61d8327deb882cf99")
        batch_input_layout.addWidget(batch_input_help)
        batch_input_layout.addWidget(batch_input_example)
        
        self.batch_input_text = QPlainTextEdit()
        self.batch_input_text.setPlaceholderText("Enter hashes to crack (one per line)...")
        batch_input_layout.addWidget(self.batch_input_text)
        
        hash_type_layout = QHBoxLayout()
        hash_type_label = QLabel("Hash Type:")
        self.batch_hash_type_combo = QComboBox()
        self.batch_hash_type_combo.addItems(["Auto Detect", "MD5", "SHA1", "SHA256", "SHA512"])
        hash_type_layout.addWidget(hash_type_label)
        hash_type_layout.addWidget(self.batch_hash_type_combo)
        batch_input_layout.addLayout(hash_type_layout)
        
        batch_file_layout = QHBoxLayout()
        self.batch_load_button = QPushButton("Load From File")
        self.batch_load_button.clicked.connect(self.load_batch_file)
        self.batch_save_button = QPushButton("Save Results")
        self.batch_save_button.clicked.connect(self.save_batch_results)
        batch_file_layout.addWidget(self.batch_load_button)
        batch_file_layout.addWidget(self.batch_save_button)
        batch_input_layout.addLayout(batch_file_layout)
        
        batch_layout.addWidget(batch_input_group)
        
        # Batch attack methods (reusing same options as single hash)
        batch_methods_group = QGroupBox("Attack Methods")
        batch_methods_layout = QVBoxLayout()
        batch_methods_group.setLayout(batch_methods_layout)
        
        # Dictionary attack options
        self.batch_dict_check = QCheckBox("Dictionary Attack")
        self.batch_dict_check.setChecked(True)
        batch_dict_layout = QHBoxLayout()
        batch_dict_path_label = QLabel("Dictionary:")
        self.batch_dict_path = QLineEdit()
        self.batch_dict_path.setPlaceholderText("Path to dictionary file...")
        batch_dict_browse = QPushButton("Browse")
        batch_dict_browse.clicked.connect(self.browse_batch_dictionary)
        batch_dict_layout.addWidget(batch_dict_path_label)
        batch_dict_layout.addWidget(self.batch_dict_path)
        batch_dict_layout.addWidget(batch_dict_browse)
        
        batch_methods_layout.addWidget(self.batch_dict_check)
        batch_methods_layout.addLayout(batch_dict_layout)
        
        # Brute force options
        self.batch_brute_check = QCheckBox("Brute Force Attack")
        self.batch_brute_check.setChecked(True)
        batch_brute_layout = QHBoxLayout()
        batch_min_len_label = QLabel("Min Length:")
        self.batch_min_len_spin = QSpinBox()
        self.batch_min_len_spin.setValue(1)
        batch_max_len_label = QLabel("Max Length:")
        self.batch_max_len_spin = QSpinBox()
        self.batch_max_len_spin.setValue(4)  # Lower default for batch processing
        batch_brute_layout.addWidget(batch_min_len_label)
        batch_brute_layout.addWidget(self.batch_min_len_spin)
        batch_brute_layout.addWidget(batch_max_len_label)
        batch_brute_layout.addWidget(self.batch_max_len_spin)
        
        batch_methods_layout.addWidget(self.batch_brute_check)
        batch_methods_layout.addLayout(batch_brute_layout)
        
        batch_layout.addWidget(batch_methods_group)
        
        # Batch results table
        batch_results_group = QGroupBox("Results")
        batch_results_layout = QVBoxLayout()
        batch_results_group.setLayout(batch_results_layout)
        
        self.batch_results_table = QTableWidget(0, 4)
        self.batch_results_table.setHorizontalHeaderLabels(["Label", "Hash", "Password", "Status"])
        self.batch_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        batch_results_layout.addWidget(self.batch_results_table)
        
        batch_layout.addWidget(batch_results_group)
        
        # Batch control buttons
        batch_button_layout = QHBoxLayout()
        self.batch_start_button = QPushButton("Start Batch Cracking")
        self.batch_start_button.clicked.connect(self.start_batch_cracking)
        self.batch_stop_button = QPushButton("Stop")
        self.batch_stop_button.clicked.connect(self.stop_batch_cracking)
        self.batch_stop_button.setEnabled(False)
        batch_button_layout.addWidget(self.batch_start_button)
        batch_button_layout.addWidget(self.batch_stop_button)
        
        batch_layout.addLayout(batch_button_layout)
        
        # Create third tab for rainbow tables
        rainbow_tab = QWidget()
        rainbow_layout = QVBoxLayout()
        rainbow_tab.setLayout(rainbow_layout)
        tabs.addTab(rainbow_tab, "Rainbow Tables")
        
        # Rainbow tables explanation
        rainbow_info = QLabel("Rainbow Tables allow for faster cracking of hashes by precomputing hash chains.")
        rainbow_info.setWordWrap(True)
        rainbow_layout.addWidget(rainbow_info)
        
        # Rainbow table management
        rainbow_manage_group = QGroupBox("Rainbow Table Management")
        rainbow_manage_layout = QVBoxLayout()
        rainbow_manage_group.setLayout(rainbow_manage_layout)
        
        rainbow_table_layout = QHBoxLayout()
        rainbow_table_label = QLabel("Table Directory:")
        self.rainbow_table_path = QLineEdit()
        self.rainbow_table_path.setPlaceholderText("Path to rainbow tables directory...")
        rainbow_table_browse = QPushButton("Browse")
        rainbow_table_browse.clicked.connect(self.browse_rainbow_directory)
        rainbow_table_layout.addWidget(rainbow_table_label)
        rainbow_table_layout.addWidget(self.rainbow_table_path)
        rainbow_table_layout.addWidget(rainbow_table_browse)
        rainbow_manage_layout.addLayout(rainbow_table_layout)
        
        # Rainbow table generation
        rainbow_gen_layout = QHBoxLayout()
        rainbow_gen_label = QLabel("Generate New Table:")
        self.rainbow_hash_type_combo = QComboBox()
        self.rainbow_hash_type_combo.addItems(["MD5", "SHA1", "SHA256"])
        rainbow_min_len_label = QLabel("Min Length:")
        self.rainbow_min_len_spin = QSpinBox()
        self.rainbow_min_len_spin.setValue(1)
        rainbow_max_len_label = QLabel("Max Length:")
        self.rainbow_max_len_spin = QSpinBox()
        self.rainbow_max_len_spin.setValue(6)
        rainbow_charset_label = QLabel("Charset:")
        self.rainbow_charset_combo = QComboBox()
        self.rainbow_charset_combo.addItems(["Lowercase", "Lowercase+Digits", "All"])
        rainbow_gen_button = QPushButton("Generate")
        rainbow_gen_button.clicked.connect(self.generate_rainbow_table)
        
        rainbow_gen_layout.addWidget(rainbow_gen_label)
        rainbow_gen_layout.addWidget(self.rainbow_hash_type_combo)
        rainbow_gen_layout.addWidget(rainbow_min_len_label)
        rainbow_gen_layout.addWidget(self.rainbow_min_len_spin)
        rainbow_gen_layout.addWidget(rainbow_max_len_label)
        rainbow_gen_layout.addWidget(self.rainbow_max_len_spin)
        rainbow_gen_layout.addWidget(rainbow_charset_label)
        rainbow_gen_layout.addWidget(self.rainbow_charset_combo)
        rainbow_gen_layout.addWidget(rainbow_gen_button)
        rainbow_manage_layout.addLayout(rainbow_gen_layout)
        
        rainbow_layout.addWidget(rainbow_manage_group)
        
        # Available rainbow tables
        rainbow_avail_group = QGroupBox("Available Rainbow Tables")
        rainbow_avail_layout = QVBoxLayout()
        rainbow_avail_group.setLayout(rainbow_avail_layout)
        
        self.rainbow_table_list = QTableWidget(0, 4)
        self.rainbow_table_list.setHorizontalHeaderLabels(["Hash Type", "Charset", "Length", "Size"])
        self.rainbow_table_list.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        rainbow_avail_layout.addWidget(self.rainbow_table_list)
        
        rainbow_refresh_button = QPushButton("Refresh Table List")
        rainbow_refresh_button.clicked.connect(self.refresh_rainbow_tables)
        rainbow_avail_layout.addWidget(rainbow_refresh_button)
        
        rainbow_layout.addWidget(rainbow_avail_group)
        
        # Lookup section
        rainbow_lookup_group = QGroupBox("Rainbow Table Lookup")
        rainbow_lookup_layout = QVBoxLayout()
        rainbow_lookup_group.setLayout(rainbow_lookup_layout)
        
        rainbow_hash_layout = QHBoxLayout()
        rainbow_hash_label = QLabel("Hash to Lookup:")
        self.rainbow_hash_input = QLineEdit()
        self.rainbow_hash_input.setPlaceholderText("Enter hash to lookup...")
        rainbow_hash_layout.addWidget(rainbow_hash_label)
        rainbow_hash_layout.addWidget(self.rainbow_hash_input)
        rainbow_lookup_layout.addLayout(rainbow_hash_layout)
        
        rainbow_button_layout = QHBoxLayout()
        rainbow_lookup_button = QPushButton("Lookup Hash")
        rainbow_lookup_button.clicked.connect(self.lookup_rainbow_hash)
        rainbow_button_layout.addWidget(rainbow_lookup_button)
        rainbow_lookup_layout.addLayout(rainbow_button_layout)
        
        rainbow_result_layout = QHBoxLayout()
        rainbow_result_label = QLabel("Result:")
        self.rainbow_result_text = QLineEdit()
        self.rainbow_result_text.setReadOnly(True)
        rainbow_result_layout.addWidget(rainbow_result_label)
        rainbow_result_layout.addWidget(self.rainbow_result_text)
        rainbow_lookup_layout.addLayout(rainbow_result_layout)
        
        rainbow_layout.addWidget(rainbow_lookup_group)
        
        # Create fourth tab for hash generation
        generator_tab = QWidget()
        generator_layout = QVBoxLayout()
        generator_tab.setLayout(generator_layout)
        tabs.addTab(generator_tab, "Hash Generator")
        
        # Password input
        gen_input_group = QGroupBox("Generate Hash")
        gen_input_layout = QVBoxLayout()
        gen_input_group.setLayout(gen_input_layout)
        
        gen_password_layout = QHBoxLayout()
        gen_password_label = QLabel("Password:")
        self.gen_password_input = QLineEdit()
        self.gen_password_input.setPlaceholderText("Enter password to hash...")
        gen_password_layout.addWidget(gen_password_label)
        gen_password_layout.addWidget(self.gen_password_input)
        gen_input_layout.addLayout(gen_password_layout)
        
        gen_type_layout = QHBoxLayout()
        gen_type_label = QLabel("Hash Type:")
        self.gen_hash_type_combo = QComboBox()
        self.gen_hash_type_combo.addItems([
            "MD5", "SHA1", "SHA256", "SHA512", 
            "MD5 (Salted)", "SHA1 (Salted)", "SHA256 (Salted)", "SHA512 (Salted)",
            "HMAC-SHA256"
        ])
        self.gen_hash_type_combo.currentIndexChanged.connect(self.toggle_salt_field)
        gen_type_layout.addWidget(gen_type_label)
        gen_type_layout.addWidget(self.gen_hash_type_combo)
        gen_input_layout.addLayout(gen_type_layout)
        
        gen_salt_layout = QHBoxLayout()
        gen_salt_label = QLabel("Salt:")
        self.gen_salt_input = QLineEdit()
        self.gen_salt_input.setPlaceholderText("Enter salt (optional)...")
        self.gen_salt_input.setEnabled(False)  # Initially disabled for MD5
        gen_salt_random = QPushButton("Random")
        gen_salt_random.clicked.connect(self.generate_random_salt)
        gen_salt_layout.addWidget(gen_salt_label)
        gen_salt_layout.addWidget(self.gen_salt_input)
        gen_salt_layout.addWidget(gen_salt_random)
        gen_input_layout.addLayout(gen_salt_layout)
        
        gen_button_layout = QHBoxLayout()
        gen_hash_button = QPushButton("Generate Hash")
        gen_hash_button.clicked.connect(self.generate_hash)
        gen_button_layout.addWidget(gen_hash_button)
        gen_input_layout.addLayout(gen_button_layout)
        
        generator_layout.addWidget(gen_input_group)
        
        # Hash output
        gen_output_group = QGroupBox("Hash Output")
        gen_output_layout = QVBoxLayout()
        gen_output_group.setLayout(gen_output_layout)
        
        self.gen_result_table = QTableWidget(5, 2)
        self.gen_result_table.setHorizontalHeaderLabels(["Property", "Value"])
        self.gen_result_table.verticalHeader().setVisible(False)
        self.gen_result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.gen_result_table.setItem(0, 0, QTableWidgetItem("Hash Type"))
        self.gen_result_table.setItem(1, 0, QTableWidgetItem("Password"))
        self.gen_result_table.setItem(2, 0, QTableWidgetItem("Salt"))
        self.gen_result_table.setItem(3, 0, QTableWidgetItem("Hash Value"))
        self.gen_result_table.setItem(4, 0, QTableWidgetItem("Time Generated"))
        
        # Initialize with empty values
        for i in range(5):
            self.gen_result_table.setItem(i, 1, QTableWidgetItem(""))
        
        gen_output_layout.addWidget(self.gen_result_table)
        
        gen_copy_layout = QHBoxLayout()
        gen_copy_button = QPushButton("Copy Hash to Clipboard")
        gen_copy_button.clicked.connect(self.copy_hash_to_clipboard)
        gen_copy_layout.addWidget(gen_copy_button)
        gen_output_layout.addLayout(gen_copy_layout)
        
        generator_layout.addWidget(gen_output_group)
        
        # Hash comparison
        gen_verify_group = QGroupBox("Verify Hash")
        gen_verify_layout = QVBoxLayout()
        gen_verify_group.setLayout(gen_verify_layout)
        
        gen_verify_password_layout = QHBoxLayout()
        gen_verify_password_label = QLabel("Password:")
        self.gen_verify_password_input = QLineEdit()
        self.gen_verify_password_input.setPlaceholderText("Enter password to verify...")
        gen_verify_password_layout.addWidget(gen_verify_password_label)
        gen_verify_password_layout.addWidget(self.gen_verify_password_input)
        gen_verify_layout.addLayout(gen_verify_password_layout)
        
        gen_verify_hash_layout = QHBoxLayout()
        gen_verify_hash_label = QLabel("Hash:")
        self.gen_verify_hash_input = QLineEdit()
        self.gen_verify_hash_input.setPlaceholderText("Enter hash to verify...")
        gen_verify_hash_layout.addWidget(gen_verify_hash_label)
        gen_verify_hash_layout.addWidget(self.gen_verify_hash_input)
        gen_verify_layout.addLayout(gen_verify_hash_layout)
        
        gen_verify_type_layout = QHBoxLayout()
        gen_verify_type_label = QLabel("Hash Type:")
        self.gen_verify_type_combo = QComboBox()
        self.gen_verify_type_combo.addItems([
            "MD5", "SHA1", "SHA256", "SHA512", 
            "MD5 (Salted)", "SHA1 (Salted)", "SHA256 (Salted)", "SHA512 (Salted)",
            "HMAC-SHA256"
        ])
        self.gen_verify_type_combo.currentIndexChanged.connect(self.toggle_verify_salt_field)
        gen_verify_type_layout.addWidget(gen_verify_type_label)
        gen_verify_type_layout.addWidget(self.gen_verify_type_combo)
        gen_verify_layout.addLayout(gen_verify_type_layout)
        
        gen_verify_salt_layout = QHBoxLayout()
        gen_verify_salt_label = QLabel("Salt:")
        self.gen_verify_salt_input = QLineEdit()
        self.gen_verify_salt_input.setPlaceholderText("Enter salt (if used)...")
        self.gen_verify_salt_input.setEnabled(False)  # Initially disabled for MD5
        gen_verify_salt_layout.addWidget(gen_verify_salt_label)
        gen_verify_salt_layout.addWidget(self.gen_verify_salt_input)
        gen_verify_layout.addLayout(gen_verify_salt_layout)
        
        gen_verify_button_layout = QHBoxLayout()
        gen_verify_button = QPushButton("Verify")
        gen_verify_button.clicked.connect(self.verify_hash)
        gen_verify_button_layout.addWidget(gen_verify_button)
        gen_verify_layout.addLayout(gen_verify_button_layout)
        
        gen_verify_result_layout = QHBoxLayout()
        gen_verify_result_label = QLabel("Result:")
        self.gen_verify_result_label = QLabel("")
        gen_verify_result_layout.addWidget(gen_verify_result_label)
        gen_verify_result_layout.addWidget(self.gen_verify_result_label)
        gen_verify_layout.addLayout(gen_verify_result_layout)
        
        generator_layout.addWidget(gen_verify_group)

        # Initialize timer for progress updates
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_progress)
        self.start_time = 0
        self.attempts = 0
        
        # Show initial status
        self.log_status("Ready to crack passwords. Enter a hash value and configure attack methods.")
        
    def browse_dictionary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Dictionary File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.dict_path.setText(file_path)
            
    def get_charset(self):
        charset = ""
        if self.lowercase_check.isChecked():
            charset += "abcdefghijklmnopqrstuvwxyz"
        if self.uppercase_check.isChecked():
            charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if self.digits_check.isChecked():
            charset += "0123456789"
        if self.symbols_check.isChecked():
            charset += "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"
        return charset
    
    def start_cracking(self):
        hash_value = self.hash_input.text().strip()
        if not hash_value:
            self.log_status("Error: Please enter a hash value.")
            return
            
        hash_type = self.hash_type_combo.currentText().lower()
        if hash_type == "auto detect":
            hash_type = None
            
        methods = []
        
        # Add dictionary attack if enabled
        if self.dict_check.isChecked():
            dict_path = self.dict_path.text().strip()
            if not dict_path:
                dict_path = "data/common_passwords.txt"
                # Create a default dictionary if it doesn't exist
                if not os.path.exists("data"):
                    os.makedirs("data")
                if not os.path.exists(dict_path):
                    with open(dict_path, "w") as f:
                        f.write("password\n123456\nadmin\nqwerty\nletmein\n")
            methods.append(("dictionary", {"dictionary_path": dict_path}))
            
        # Add rule-based attack if enabled
        if self.rule_check.isChecked():
            base_words_text = self.base_words.text().strip()
            if base_words_text:
                base_words = [word.strip() for word in base_words_text.split(",")]
                methods.append(("rule_based", {"base_words": base_words}))
            
        # Add brute force attack if enabled
        if self.brute_check.isChecked():
            charset = self.get_charset()
            if not charset:
                charset = "abcdefghijklmnopqrstuvwxyz0123456789"
            methods.append((
                "brute_force", 
                {
                    "char_set": charset,
                    "min_length": self.min_len_spin.value(),
                    "max_length": self.max_len_spin.value()
                }
            ))
            
        if not methods:
            self.log_status("Error: Please select at least one attack method.")
            return
            
        # Reset progress
        self.progress_bar.setValue(0)
        self.start_time = time.time()
        self.attempts = 0
        self.result_text.clear()
        
        # Disable start button, enable stop button
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Start the cracking thread
        self.cracker_thread = CrackerThread(self.cracker, hash_value, hash_type, methods)
        self.cracker_thread.update_signal.connect(self.handle_update)
        self.cracker_thread.finished_signal.connect(self.handle_finished)
        self.cracker_thread.start()
        
        # Start the timer for progress updates
        self.timer.start(100)  # Update every 100ms
        
        self.log_status(f"Starting password cracking for hash: {hash_value}")
        
    def stop_cracking(self):
        if self.cracker_thread and self.cracker_thread.isRunning():
            self.log_status("Stopping password cracking...")
            self.cracker_thread.stop()
            self.cracker_thread.wait()
            
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.timer.stop()
        
    def handle_update(self, update):
        if update.get("status"):
            self.log_status(update["status"])
            
        if update.get("attempts"):
            self.attempts = update["attempts"]
            
        if update.get("found"):
            self.result_text.setText(update["password"])
            self.log_status(f"Password found: {update['password']}")
            
    def handle_finished(self, result):
        self.timer.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        if result["success"]:
            self.result_text.setText(result["password"])
            self.log_status(f"Password cracking completed successfully in {result['time_elapsed']:.2f} seconds")
        else:
            self.log_status("Password cracking completed. No match found.")
            
    def update_progress(self):
        elapsed = time.time() - self.start_time
        self.progress_bar.setFormat(f"{self.attempts} attempts | Elapsed: {elapsed:.1f}s")
        self.progress_bar.setValue(min(self.attempts % 100, 99))  # Cycle between 0-99
        
    def log_status(self, message):
        self.status_text.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        self.status_text.moveCursor(QTextCursor.End)

    # Hash Generator methods
    def toggle_salt_field(self, index):
        hash_type = self.gen_hash_type_combo.currentText()
        needs_salt = "Salted" in hash_type or "HMAC" in hash_type
        self.gen_salt_input.setEnabled(needs_salt)
        if needs_salt and not self.gen_salt_input.text():
            self.generate_random_salt()
    
    def toggle_verify_salt_field(self, index):
        hash_type = self.gen_verify_type_combo.currentText()
        needs_salt = "Salted" in hash_type or "HMAC" in hash_type
        self.gen_verify_salt_input.setEnabled(needs_salt)
    
    def generate_random_salt(self):
        salt = binascii.hexlify(os.urandom(8)).decode()
        self.gen_salt_input.setText(salt)
    
    def generate_hash(self):
        password = self.gen_password_input.text()
        if not password:
            self.log_status("Error: Please enter a password to hash.")
            return
        
        hash_type_map = {
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "MD5 (Salted)": "md5_salted",
            "SHA1 (Salted)": "sha1_salted",
            "SHA256 (Salted)": "sha256_salted",
            "SHA512 (Salted)": "sha512_salted",
            "HMAC-SHA256": "hmac_sha256"
        }
        
        hash_type_text = self.gen_hash_type_combo.currentText()
        hash_type = hash_type_map.get(hash_type_text, "md5")
        
        salt = self.gen_salt_input.text() if self.gen_salt_input.isEnabled() else None
        
        try:
            result = self.hash_generator.generate_hash(password, hash_type, salt)
            
            # Display results in the table
            self.gen_result_table.setItem(0, 1, QTableWidgetItem(hash_type_text))
            self.gen_result_table.setItem(1, 1, QTableWidgetItem(result["password"]))
            self.gen_result_table.setItem(2, 1, QTableWidgetItem(result["salt"] or "N/A"))
            self.gen_result_table.setItem(3, 1, QTableWidgetItem(result["hash_value"]))
            self.gen_result_table.setItem(4, 1, QTableWidgetItem(time.strftime("%Y-%m-%d %H:%M:%S")))
            
            self.log_status(f"Hash generated: {result['hash_value']}")
        except Exception as e:
            self.log_status(f"Error generating hash: {str(e)}")
    
    def copy_hash_to_clipboard(self):
        hash_item = self.gen_result_table.item(3, 1)
        if hash_item and hash_item.text():
            clipboard = QApplication.clipboard()
            clipboard.setText(hash_item.text())
            self.log_status("Hash copied to clipboard.")
        else:
            self.log_status("No hash to copy.")
    
    def verify_hash(self):
        password = self.gen_verify_password_input.text()
        hash_value = self.gen_verify_hash_input.text()
        
        if not password or not hash_value:
            self.log_status("Error: Please enter both password and hash.")
            return
        
        hash_type_map = {
            "MD5": "md5",
            "SHA1": "sha1",
            "SHA256": "sha256",
            "SHA512": "sha512",
            "MD5 (Salted)": "md5_salted",
            "SHA1 (Salted)": "sha1_salted",
            "SHA256 (Salted)": "sha256_salted",
            "SHA512 (Salted)": "sha512_salted",
            "HMAC-SHA256": "hmac_sha256"
        }
        
        hash_type_text = self.gen_verify_type_combo.currentText()
        hash_type = hash_type_map.get(hash_type_text, "md5")
        
        salt = self.gen_verify_salt_input.text() if self.gen_verify_salt_input.isEnabled() else None
        
        try:
            result = self.hash_generator.verify_hash(password, hash_value, hash_type, salt)
            
            if result:
                self.gen_verify_result_label.setText("MATCH")
                self.gen_verify_result_label.setStyleSheet("color: green; font-weight: bold;")
                self.log_status("Password matches hash.")
            else:
                self.gen_verify_result_label.setText("NO MATCH")
                self.gen_verify_result_label.setStyleSheet("color: red; font-weight: bold;")
                self.log_status("Password does not match hash.")
        except Exception as e:
            self.log_status(f"Error verifying hash: {str(e)}")
            self.gen_verify_result_label.setText("ERROR")
            self.gen_verify_result_label.setStyleSheet("color: orange; font-weight: bold;")
    
    # Batch processing methods
    def load_batch_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Hashes from File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    self.batch_input_text.setPlainText(f.read())
                self.log_status(f"Loaded hashes from {file_path}")
            except Exception as e:
                self.log_status(f"Error loading file: {str(e)}")
    
    def save_batch_results(self):
        if self.batch_results_table.rowCount() == 0:
            self.log_status("No results to save.")
            return
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # Write header
                if file_path.endswith('.csv'):
                    f.write("Label,Hash,Password,Status\n")
                else:
                    f.write("Label\tHash\tPassword\tStatus\n")
                
                # Write data
                for row in range(self.batch_results_table.rowCount()):
                    label = self.batch_results_table.item(row, 0).text()
                    hash_val = self.batch_results_table.item(row, 1).text()
                    password = self.batch_results_table.item(row, 2).text()
                    status = self.batch_results_table.item(row, 3).text()
                    
                    if file_path.endswith('.csv'):
                        f.write(f'"{label}","{hash_val}","{password}","{status}"\n')
                    else:
                        f.write(f'{label}\t{hash_val}\t{password}\t{status}\n')
            
            self.log_status(f"Results saved to {file_path}")
        except Exception as e:
            self.log_status(f"Error saving file: {str(e)}")
    
    def browse_batch_dictionary(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Dictionary File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.batch_dict_path.setText(file_path)
    
    def start_batch_cracking(self):
        batch_text = self.batch_input_text.toPlainText().strip()
        if not batch_text:
            self.log_status("Error: Please enter at least one hash.")
            return
        
        # Parse hashes
        lines = batch_text.split('\n')
        hashes = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if ":" in line:
                label, hash_val = line.split(":", 1)
            else:
                label = f"Hash {len(hashes) + 1}"
                hash_val = line
            
            hashes.append((label, hash_val.strip()))
        
        if not hashes:
            self.log_status("Error: No valid hashes found.")
            return
        
        # Setup table
        self.batch_results_table.setRowCount(len(hashes))
        for i, (label, hash_val) in enumerate(hashes):
            self.batch_results_table.setItem(i, 0, QTableWidgetItem(label))
            self.batch_results_table.setItem(i, 1, QTableWidgetItem(hash_val))
            self.batch_results_table.setItem(i, 2, QTableWidgetItem(""))
            self.batch_results_table.setItem(i, 3, QTableWidgetItem("Pending"))
        
        # Get hash type
        hash_type = self.batch_hash_type_combo.currentText().lower()
        if hash_type == "auto detect":
            hash_type = None
        
        # Prepare methods
        methods = []
        
        # Add dictionary attack if enabled
        if self.batch_dict_check.isChecked():
            dict_path = self.batch_dict_path.text().strip()
            if not dict_path:
                dict_path = "data/common_passwords.txt"
                # Create a default dictionary if it doesn't exist
                if not os.path.exists("data"):
                    os.makedirs("data")
                if not os.path.exists(dict_path):
                    with open(dict_path, "w") as f:
                        f.write("password\n123456\nadmin\nqwerty\nletmein\n")
            methods.append(("dictionary", {"dictionary_path": dict_path}))
        
        # Add brute force attack if enabled
        if self.batch_brute_check.isChecked():
            charset = self.get_charset()  # Reuse from single hash tab
            if not charset:
                charset = "abcdefghijklmnopqrstuvwxyz0123456789"
            methods.append((
                "brute_force", 
                {
                    "char_set": charset,
                    "min_length": self.batch_min_len_spin.value(),
                    "max_length": self.batch_max_len_spin.value()
                }
            ))
        
        if not methods:
            self.log_status("Error: Please select at least one attack method.")
            return
        
        # Disable UI
        self.batch_start_button.setEnabled(False)
        self.batch_stop_button.setEnabled(True)
        self.batch_input_text.setReadOnly(True)
        
        # Start processing (simplified approach - processing one by one)
        self.log_status(f"Starting batch processing of {len(hashes)} hashes...")
        
        # In a real application, you'd want to use a thread pool
        # This is a simplified version for demonstration
        for i, (label, hash_val) in enumerate(hashes):
            # Update status
            self.batch_results_table.setItem(i, 3, QTableWidgetItem("Processing"))
            QApplication.processEvents()  # Allow UI to update
            
            # Process hash
            result = self.cracker.crack_password(hash_val, hash_type, methods)
            
            # Update result
            if result["success"]:
                self.batch_results_table.setItem(i, 2, QTableWidgetItem(result["password"]))
                self.batch_results_table.setItem(i, 3, QTableWidgetItem("Cracked"))
                self.log_status(f"Cracked hash {i+1}/{len(hashes)}: {label}")
            else:
                self.batch_results_table.setItem(i, 3, QTableWidgetItem("Not Found"))
                self.log_status(f"Failed to crack hash {i+1}/{len(hashes)}: {label}")
        
        # Re-enable UI
        self.batch_start_button.setEnabled(True)
        self.batch_stop_button.setEnabled(False)
        self.batch_input_text.setReadOnly(False)
        
        self.log_status("Batch processing completed.")
    
    def stop_batch_cracking(self):
        # In a real implementation, you'd signal the threads to stop
        self.log_status("Stopping batch processing...")
        self.batch_start_button.setEnabled(True)
        self.batch_stop_button.setEnabled(False)
        self.batch_input_text.setReadOnly(False)
    
    # Rainbow tables methods
    def browse_rainbow_directory(self):
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Rainbow Tables Directory", ""
        )
        if dir_path:
            self.rainbow_table_path.setText(dir_path)
            self.refresh_rainbow_tables()
    
    def refresh_rainbow_tables(self):
        dir_path = self.rainbow_table_path.text()
        if not dir_path or not os.path.isdir(dir_path):
            self.log_status("Please select a valid rainbow tables directory.")
            return
        
        try:
            # In a real implementation, this would scan for actual rainbow table files
            # For demo purposes, just show some placeholder data
            self.rainbow_table_list.setRowCount(0)
            
            sample_tables = [
                ("MD5", "Lowercase", "1-6", "250 MB"),
                ("MD5", "Alphanumeric", "1-5", "2.1 GB"),
                ("SHA1", "Lowercase", "1-5", "1.5 GB")
            ]
            
            self.rainbow_table_list.setRowCount(len(sample_tables))
            for i, (hash_type, charset, length, size) in enumerate(sample_tables):
                self.rainbow_table_list.setItem(i, 0, QTableWidgetItem(hash_type))
                self.rainbow_table_list.setItem(i, 1, QTableWidgetItem(charset))
                self.rainbow_table_list.setItem(i, 2, QTableWidgetItem(length))
                self.rainbow_table_list.setItem(i, 3, QTableWidgetItem(size))
            
            self.log_status(f"Found {len(sample_tables)} rainbow tables.")
        except Exception as e:
            self.log_status(f"Error refreshing rainbow tables: {str(e)}")
    
    def generate_rainbow_table(self):
        hash_type = self.rainbow_hash_type_combo.currentText()
        min_len = self.rainbow_min_len_spin.value()
        max_len = self.rainbow_max_len_spin.value()
        charset = self.rainbow_charset_combo.currentText()
        
        # Show an info dialog explaining this is a demo
        QMessageBox.information(
            self,
            "Rainbow Table Generation",
            f"In a full implementation, this would generate a {hash_type} rainbow table for "
            f"passwords of length {min_len}-{max_len} using {charset} charset.\n\n"
            "This is a time and resource-intensive process that can take hours or days.\n\n"
            "For this demo, the generation feature is simulated."
        )
        
        self.log_status(f"Rainbow table generation for {hash_type} simulated.")
    
    def lookup_rainbow_hash(self):
        hash_val = self.rainbow_hash_input.text().strip()
        if not hash_val:
            self.log_status("Please enter a hash to lookup.")
            return
        
        dir_path = self.rainbow_table_path.text()
        if not dir_path or not os.path.isdir(dir_path):
            self.log_status("Please select a valid rainbow tables directory.")
            return
        
        # In a real implementation, this would search the rainbow tables
        # For demo purposes, just show a simulated result
        self.log_status(f"Looking up hash in rainbow tables: {hash_val}")
        
        # Simulate a lookup time
        QApplication.processEvents()
        time.sleep(1.5)
        
        # Randomly succeed or fail for demo purposes
        import random
        if random.random() > 0.5:
            password = "password123" if hash_val.startswith("5f") else "letmein"
            self.rainbow_result_text.setText(password)
            self.log_status(f"Found password in rainbow table: {password}")
        else:
            self.rainbow_result_text.setText("")
            self.log_status("Hash not found in rainbow tables.")


def main():
    app = QApplication(sys.argv)
    window = PasswordCrackerGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main() 