from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt, QFile, QTextStream
from core.decryption import decrypt_file


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
        # self.decrypt_text_btn = QPushButton("Decrypt Text")
        # self.decrypt_text_btn.clicked.connect(self.on_decrypt_text)
        #
        # # Result display
        # self.result_output = QTextEdit()
        # self.result_output.setReadOnly(True)
        # self.result_output.setPlaceholderText("Decrypted result will appear here...")
        #
        # text_layout.addWidget(self.text_input)
        # text_layout.addLayout(key_layout)
        # text_layout.addWidget(self.decrypt_text_btn)
        # text_layout.addWidget(self.result_output)
        # text_group.setLayout(text_layout)

        # Add sections to main layout
        layout.addWidget(QLabel("File Decryption:"))
        layout.addWidget(file_group)
        layout.addSpacing(20)
        # layout.addWidget(QLabel("Text Decryption:"))
        # layout.addWidget(text_group)

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

        # if not key:
        #     self.show_error("Please enter decryption key")
        #     return

        try:
            output_path = decrypt_file(self.file_path)
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

    # def on_decrypt_text(self):
    #     text = self.text_input.toPlainText().strip()
    #     key = self.key_input.text().strip()
    #
    #     if not text:
    #         self.show_error("Please enter text to decrypt")
    #         return
    #
    #     if not key:
    #         self.show_error("Please enter decryption key")
    #         return
    #
    #     try:
    #         decrypted = decrypt_text(text, key)
    #         self.result_output.setPlainText(decrypted)
    #         self.show_success("Text decrypted successfully!")
    #     except Exception as e:
    #         self.show_error(f"Decryption failed: {str(e)}")

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