from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog,
    QMessageBox
)
from PyQt6.QtCore import Qt, QFile, QTextStream
from .decrypt import DecryptTab
from .encrypt import EncryptTab



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
