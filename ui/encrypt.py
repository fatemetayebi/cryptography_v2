from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QMessageBox, QComboBox, QGroupBox
)
import json
import os
from core.encryption import encrypt_file
import tempfile
import shutil
from PyQt6.QtWidgets import QFileDialog


class EncryptTab(QWidget):
    def __init__(self, status_label, tab_widget):
        super().__init__()
        self.status_label = status_label
        self.tab_widget = tab_widget
        self.file_path = ""
        self.users_file = "users/user.json"
        self.users = []
        self.load_users()
        self.setup_ui()

    def load_users(self):
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self.users = [user["username"] for user in data if "username" in user]
                    else:
                        self.users = []
            else:
                self.users = []
                print(f"File {self.users_file} not found")
        except Exception as e:
            print(f"Error loading users: {e}")
            self.users = []

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # File Encryption Section
        file_group = QGroupBox("File Encryption")
        file_layout = QVBoxLayout()

        # File selection button
        file_select_layout = QHBoxLayout()
        self.file_button = QPushButton("Select File")
        self.file_button.clicked.connect(self.select_file)
        self.file_label = QLabel("No file selected")
        file_select_layout.addWidget(self.file_button)
        file_select_layout.addWidget(self.file_label)

        # MAC Mode Selection
        mac_layout = QHBoxLayout()
        mac_label = QLabel("MAC Mode:")
        self.mac_combo = QComboBox()
        self.mac_combo.addItems(["OMAC", "CCM", "HMAC"])
        self.mac_combo.setCurrentIndex(0)
        mac_layout.addWidget(mac_label)
        mac_layout.addWidget(self.mac_combo)
        mac_layout.addStretch()

        # Encryption Mode Selection
        encryption_layout = QHBoxLayout()
        encryption_label = QLabel("Encryption Mode:")
        self.encryption_combo = QComboBox()
        self.encryption_combo.addItems(["SecureEnvelop", "RSA", "AES", "DES", "3DES"])
        self.encryption_combo.setCurrentIndex(0)
        self.encryption_combo.currentTextChanged.connect(self.on_encryption_mode_changed)
        encryption_layout.addWidget(encryption_label)
        encryption_layout.addWidget(self.encryption_combo)
        encryption_layout.addStretch()

        # Cipher Mode Selection (only for symmetric)
        cipher_layout = QHBoxLayout()
        cipher_label = QLabel("Cipher Mode:")
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems(["CTR", "CFB", "CBC"])
        self.cipher_combo.setCurrentIndex(0)
        cipher_layout.addWidget(cipher_label)
        cipher_layout.addWidget(self.cipher_combo)
        cipher_layout.addStretch()

        # Encrypt For User Selection (only for RSA and SecureEnvelop)
        self.user_layout = QHBoxLayout()
        user_label = QLabel("Encrypt For:")
        self.user_combo = QComboBox()
        self.user_combo.addItems(self.users if self.users else ["No users available"])
        self.user_combo.setEnabled(False)  # ابتدا غیرفعال است
        self.user_layout.addWidget(user_label)
        self.user_layout.addWidget(self.user_combo)
        self.user_layout.addStretch()

        # Key input (only for symmetric mode)
        self.key_layout = QHBoxLayout()
        self.key_label = QLabel("Encryption Key:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter secret key for symmetric encryption")
        self.key_layout.addWidget(self.key_label)
        self.key_layout.addWidget(self.key_input)

        # File encryption button
        self.encrypt_file_btn = QPushButton("Encrypt Selected File")
        self.encrypt_file_btn.clicked.connect(self.on_encrypt_file)
        self.encrypt_file_btn.setEnabled(False)

        file_layout.addLayout(file_select_layout)
        file_layout.addLayout(mac_layout)
        file_layout.addLayout(encryption_layout)
        file_layout.addLayout(cipher_layout)
        file_layout.addLayout(self.user_layout)
        file_layout.addWidget(self.encrypt_file_btn)
        file_group.setLayout(file_layout)

        # Add file section to main layout
        layout.addWidget(file_group)
        self.setLayout(layout)

        self.on_encryption_mode_changed()

    def on_encryption_mode_changed(self):
        encryption_mode = self.encryption_combo.currentText()

        if encryption_mode in ["RSA", "SecureEnvelop"]:
            self.user_combo.setEnabled(True)
            self.key_input.setEnabled(False)
            self.key_input.clear()
            self.cipher_combo.setEnabled(False)
        else:  # symmetric
            self.user_combo.setEnabled(False)
            self.key_input.setEnabled(True)
            self.cipher_combo.setEnabled(True)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Encrypt",
            "",
            "All Files (*);;Text Files (*.txt)"
        )

        if file_path:
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            base, ext = os.path.splitext(filename)
            temp_path = os.path.join(directory, f"{base}_copy{ext}")

            try:
                shutil.copy2(file_path, temp_path)
                self.file_path = temp_path
                self.file_label.setText(filename)
                self.encrypt_file_btn.setEnabled(True)
                self.show_status(f"Created local copy: {temp_path}", "success")

            except Exception as e:
                self.show_status(f"Error creating local copy: {e}", "error")
                self.file_path = None
                self.encrypt_file_btn.setEnabled(False)


    def on_encrypt_file(self):

        encryption_mode = self.encryption_combo.currentText()
        mac_mode = self.mac_combo.currentText()
        cipher_mode = self.cipher_combo.currentText()
        try:
            output_path = encrypt_file(
                self.file_path,
                encryption_mode=encryption_mode,
                cipher_mode=cipher_mode,
                receiver=self.user_combo.currentText() if encryption_mode in ["RSA", "SecureEnvelop"] else None,
                mac_mode = mac_mode,
            )
            success_message = f"File encrypted successfully!\n"
            success_message += f"MAC Mode: {mac_mode}\n"
            success_message += f"Encryption Mode: {encryption_mode}\n"

            if encryption_mode in ["RSA", "SecureEnvelop"]:
                success_message += f"Encrypted For: {self.user_combo.currentText()}\n"
            else:
                success_message += f"Cipher Mode: {cipher_mode}\n"

            success_message += f"Saved to: {output_path}"

            self.show_success(success_message)

            # Reset after successful encryption
            self.file_path = ""
            self.file_label.setText("No file selected")
            self.encrypt_file_btn.setEnabled(False)
            if encryption_mode == 'AES' or encryption_mode == 'DES' or encryption_mode == '3DES':
                self.key_input.clear()

        except Exception as e:
            self.show_error(f"Encryption failed: {str(e)}")

    def refresh_users(self):
        self.load_users()
        current_text = self.user_combo.currentText()
        self.user_combo.clear()
        self.user_combo.addItems(self.users if self.users else ["No users available"])

        if current_text in self.users:
            self.user_combo.setCurrentText(current_text)

    def show_success(self, message):
        self.status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
        self.status_label.setText(message)
        self.tab_widget.setCurrentIndex(0)

    def show_error(self, message):
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        self.status_label.setText(message)
        self.tab_widget.setCurrentIndex(0)

    def show_status(self, message, status_type="info"):
        if status_type == "success":
            self.status_label.setStyleSheet("color: #27ae60;")
        else:
            self.status_label.setStyleSheet("")
        self.status_label.setText(message)
