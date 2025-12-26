import sys
from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, QLineEdit, QLabel


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("مثال Qt")
        self.setGeometry(100, 100, 400, 200)

        # ایجاد ویجت‌ها
        self.setup_ui()

    def setup_ui(self):
        # ویجت مرکزی
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # لایه‌بندی
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # ویجت‌های ورودی
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("متن خود را وارد کنید...")

        # دکمه
        self.process_button = QPushButton("پردازش کن")

        # برچسب نتیجه
        self.result_label = QLabel("نتیجه اینجا نمایش داده می‌شود")

        # اضافه کردن به لایه
        layout.addWidget(self.input_field)
        layout.addWidget(self.process_button)
        layout.addWidget(self.result_label)

        # اتصال سیگنال‌ها
        self.process_button.clicked.connect(self.on_button_clicked)

    def on_button_clicked(self):
        # گرفتن ورودی از UI
        user_input = self.input_field.text()

        # فراخوانی تابع منطق (جدا از UI)
        result = process_user_input(user_input)

        # نمایش نتیجه در UI
        self.result_label.setText(result)


# تابع منطق - کاملاً جدا از UI
def process_user_input(text: str) -> str:
    """این تابع فقط منطق برنامه را پیاده‌سازی می‌کند"""
    if not text:
        return "لطفاً متنی وارد کنید!"

    # انجام محاسبات یا پردازش‌های لازم
    processed_text = f"پردازش شد: {text.upper()}"
    return processed_text


# اجرای برنامه
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
