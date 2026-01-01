from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt, QFile, QTextStream
from utilities import encrypt_file, decrypt_file, encrypt_text, decrypt_text


class EncryptTab(QWidget):
    def __init__(self, status_label, tab_widget):
        super().__init__()
        self.status_label = status_label
        self.tab_widget = tab_widget
        self.file_path = ""
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # 1. File Selection Section
        file_group = QWidget()
        file_layout = QVBoxLayout()

        # File selection button
        file_select_layout = QHBoxLayout()
        self.file_button = QPushButton("Select File")
        self.file_button.clicked.connect(self.select_file)
        self.file_label = QLabel("No file selected")
        file_select_layout.addWidget(self.file_button)
        file_select_layout.addWidget(self.file_label)

        # File encryption button
        self.encrypt_file_btn = QPushButton("Encrypt Selected File")
        self.encrypt_file_btn.clicked.connect(self.on_encrypt_file)
        self.encrypt_file_btn.setEnabled(False)

        file_layout.addLayout(file_select_layout)
        file_layout.addWidget(self.encrypt_file_btn)
        file_group.setLayout(file_layout)

        # 2. Text Encryption Section
        text_group = QWidget()
        text_layout = QVBoxLayout()

        # Text input
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter text to encrypt here...")

        # Key input
        key_layout = QHBoxLayout()
        self.key_label = QLabel("Encryption Key:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter secret key")
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)

        # Text encryption button
        self.encrypt_text_btn = QPushButton("Encrypt Text")
        self.encrypt_text_btn.clicked.connect(self.on_encrypt_text)

        # Result display
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Encrypted result will appear here...")

        text_layout.addWidget(self.text_input)
        text_layout.addLayout(key_layout)
        text_layout.addWidget(self.encrypt_text_btn)
        text_layout.addWidget(self.result_output)
        text_group.setLayout(text_layout)

        # Add sections to main layout
        layout.addWidget(QLabel("File Encryption:"))
        layout.addWidget(file_group)
        layout.addSpacing(20)
        layout.addWidget(QLabel("Text Encryption:"))
        layout.addWidget(text_group)

        self.setLayout(layout)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Encrypt",
            "",
            "All Files (*);;Text Files (*.txt)"
        )

        if file_path:
            self.file_path = file_path
            self.file_label.setText(file_path.split('/')[-1])  # Show only filename
            self.encrypt_file_btn.setEnabled(True)
            self.show_status("File selected", "success")

    def on_encrypt_file(self):
        key = self.key_input.text().strip()

        if not key:
            self.show_error("Please enter encryption key")
            return

        try:
            output_path = encrypt_file(self.file_path, key)
            self.show_success(
                f"File encrypted successfully!\n"
                f"Saved to: {output_path}"
            )
            # Reset after successful encryption
            self.file_path = ""
            self.file_label.setText("No file selected")
            self.encrypt_file_btn.setEnabled(False)
        except Exception as e:
            self.show_error(f"Encryption failed: {str(e)}")

    def on_encrypt_text(self):
        text = self.text_input.toPlainText().strip()
        key = self.key_input.text().strip()

        if not text:
            self.show_error("Please enter text to encrypt")
            return

        if not key:
            self.show_error("Please enter encryption key")
            return

        try:
            encrypted = encrypt_text(text, key)
            self.result_output.setPlainText(encrypted)
            self.show_success("Text encrypted successfully!")
        except Exception as e:
            self.show_error(f"Encryption failed: {str(e)}")

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


class DecryptTab(QWidget):
    def __init__(self, status_label, tab_widget):
        super().__init__()
        self.status_label = status_label
        self.tab_widget = tab_widget
        self.file_path = ""
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # 1. File Selection Section
        file_group = QWidget()
        file_layout = QVBoxLayout()

        # File selection button
        file_select_layout = QHBoxLayout()
        self.file_button = QPushButton("Select File")
        self.file_button.clicked.connect(self.select_file)
        self.file_label = QLabel("No file selected")
        file_select_layout.addWidget(self.file_button)
        file_select_layout.addWidget(self.file_label)

        # File decryption button
        self.decrypt_file_btn = QPushButton("Decrypt Selected File")
        self.decrypt_file_btn.clicked.connect(self.on_decrypt_file)
        self.decrypt_file_btn.setEnabled(False)

        file_layout.addLayout(file_select_layout)
        file_layout.addWidget(self.decrypt_file_btn)
        file_group.setLayout(file_layout)

        # 2. Text Decryption Section
        text_group = QWidget()
        text_layout = QVBoxLayout()

        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Enter encrypted text here...")

        # Key input
        key_layout = QHBoxLayout()
        self.key_label = QLabel("Decryption Key:")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Enter secret key")
        key_layout.addWidget(self.key_label)
        key_layout.addWidget(self.key_input)

        # Text decryption button
        self.decrypt_text_btn = QPushButton("Decrypt Text")
        self.decrypt_text_btn.clicked.connect(self.on_decrypt_text)

        # Result display
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText("Decrypted result will appear here...")

        text_layout.addWidget(self.text_input)
        text_layout.addLayout(key_layout)
        text_layout.addWidget(self.decrypt_text_btn)
        text_layout.addWidget(self.result_output)
        text_group.setLayout(text_layout)

        # Add sections to main layout
        layout.addWidget(QLabel("File Decryption:"))
        layout.addWidget(file_group)
        layout.addSpacing(20)
        layout.addWidget(QLabel("Text Decryption:"))
        layout.addWidget(text_group)

        self.setLayout(layout)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Decrypt",
            "",
            "Encrypted Files (*.enc);;All Files (*)"
        )

        if file_path:
            self.file_path = file_path
            self.file_label.setText(file_path.split('/')[-1])  # Show only filename
            self.decrypt_file_btn.setEnabled(True)
            self.show_status("File selected", "success")

    def on_decrypt_file(self):
        key = self.key_input.text().strip()

        if not key:
            self.show_error("Please enter decryption key")
            return

        try:
            output_path = decrypt_file(self.file_path, key)
            self.show_success(
                f"File decrypted successfully!\n"
                f"Saved to: {output_path}"
            )
            # Reset after successful decryption
            self.file_path = ""
            self.file_label.setText("No file selected")
            self.decrypt_file_btn.setEnabled(False)
        except Exception as e:
            self.show_error(f"Decryption failed: {str(e)}")

    def on_decrypt_text(self):
        text = self.text_input.toPlainText().strip()
        key = self.key_input.text().strip()

        if not text:
            self.show_error("Please enter text to decrypt")
            return

        if not key:
            self.show_error("Please enter decryption key")
            return

        try:
            decrypted = decrypt_text(text, key)
            self.result_output.setPlainText(decrypted)
            self.show_success("Text decrypted successfully!")
        except Exception as e:
            self.show_error(f"Decryption failed: {str(e)}")

    def show_success(self, message):
        self.status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
        self.status_label.setText(message)
        self.tab_widget.setCurrentIndex(1)

    def show_error(self, message):
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        self.status_label.setText(message)
        self.tab_widget.setCurrentIndex(1)

    def show_status(self, message, status_type="info"):
        if status_type == "success":
            self.status_label.setStyleSheet("color: #27ae60;")
        else:
            self.status_label.setStyleSheet("")
        self.status_label.setText(message)

class CryptoWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cryptography Tool")
        self.resize(800, 600)
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Title
        self.title_label = QLabel("Advanced Cryptography Tool")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("padding: 5px;")

        # Tab widget
        self.tab_widget = QTabWidget()
        self.encrypt_tab = EncryptTab(self.status_label, self.tab_widget)
        self.decrypt_tab = DecryptTab(self.status_label, self.tab_widget)

        self.tab_widget.addTab(self.encrypt_tab, "🔒 Encryption")
        self.tab_widget.addTab(self.decrypt_tab, "🔓 Decryption")

        # Add widgets to main layout
        main_layout.addWidget(self.title_label)
        main_layout.addWidget(self.tab_widget)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

    def apply_styles(self):
        style_file = QFile("ui/styles.css")
        if not style_file.open(QFile.OpenModeFlag.ReadOnly | QFile.OpenModeFlag.Text):
            print("فایل استایل پیدا نشد!")
            return

        stream = QTextStream(style_file)
        stylesheet = stream.readAll()
        style_file.close()

        self.setStyleSheet(stylesheet)
