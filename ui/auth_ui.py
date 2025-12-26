
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton
)
from PyQt6.QtCore import Qt
from PyQt6.QtCore import QFile, QTextStream
from core.auth import authenticate_user


class LoginWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.apply_styles()

    def setup_ui(self):
        # Main layout
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(30, 30, 30, 30)

        # Title label
        self.title_label = QLabel("User Authentication")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Username section
        username_layout = QHBoxLayout()
        self.username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter your username")
        username_layout.addWidget(self.username_label)
        username_layout.addWidget(self.username_input)

        # Password section
        password_layout = QHBoxLayout()
        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(self.password_label)
        password_layout.addWidget(self.password_input)

        # Buttons layout
        buttons_layout = QHBoxLayout()
        self.login_button = QPushButton("Login")
        buttons_layout.addWidget(self.login_button)

        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Add all widgets to main layout
        main_layout.addWidget(self.title_label)
        main_layout.addLayout(username_layout)
        main_layout.addLayout(password_layout)
        main_layout.addLayout(buttons_layout)
        main_layout.addWidget(self.status_label)

        self.setLayout(main_layout)

        # Connect signals
        self.login_button.clicked.connect(self.on_login_clicked)
        self.username_input.returnPressed.connect(self.on_login_clicked)
        self.password_input.returnPressed.connect(self.on_login_clicked)

        self.apply_styles()

    def on_login_clicked(self):
        """Handle login button click"""
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            self.show_error("Please enter both username and password")
            return
        result = authenticate_user(username, password)
        if result["success"]:
            self.show_success("Login successful!")
            self.clear_fields()
        else:
            self.show_error(result["message"])


    def show_success(self, message: str):
        """Show success message"""
        self.status_label.setStyleSheet("color: #27ae60; font-weight: bold;")
        self.status_label.setText(message)

    def show_error(self, message: str):
        """Show error message"""
        self.status_label.setStyleSheet("color: #e74c3c; font-weight: bold;")
        self.status_label.setText(message)

    def clear_fields(self):
        """Clear input fields"""
        self.username_input.clear()
        self.password_input.clear()
        self.status_label.clear()


    def apply_styles(self):
        style_file = QFile("ui/styles.css")
        if not style_file.open(QFile.OpenModeFlag.ReadOnly | QFile.OpenModeFlag.Text):
            print("فایل استایل پیدا نشد!")
            return

        stream = QTextStream(style_file)
        stylesheet = stream.readAll()
        style_file.close()

        self.setStyleSheet(stylesheet)



