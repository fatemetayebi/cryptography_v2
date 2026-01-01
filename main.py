import sys
from PyQt6.QtWidgets import (
    QApplication
)
from PyQt6.QtGui import QFont
from ui.auth_ui import LoginWidget


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # Set application-wide font
    font = QFont("Arial", 10)
    app.setFont(font)

    login_widget = LoginWidget()
    login_widget.setWindowTitle("Crypto System")
    login_widget.resize(400, 300)
    login_widget.show()

    sys.exit(app.exec())