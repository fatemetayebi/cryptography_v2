import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import json
from set_user import app_config
from utilities import get_private_key, get_public_key
from utilities import get_file_header


class DigitalSignature:
    """کلاس برای ایجاد و بررسی امضای دیجیتال"""

    @staticmethod
    def sign_data(data: bytes, private_key) -> bytes:
        """
        امضای داده با کلید خصوصی

        Args:
            data: داده برای امضا
            private_key: کلید خصوصی

        Returns:
            امضای تولید شده
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
        """
        بررسی امضا با کلید عمومی

        Args:
            data: داده اصلی
            signature: امضا
            public_key: کلید عمومی

        Returns:
            bool: True اگر امضا معتبر باشد
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False


def calculate_file_hash(file_path: str, hash_algorithm: str = "SHA256") -> bytes:
    """
    محاسبه هش فایل

    Args:
        file_path: مسیر فایل
        hash_algorithm: الگوریتم هش (SHA256, SHA512, SHA384, SHA1, MD5)

    Returns:
        هش محاسبه شده
    """
    hash_functions = {
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
        "SHA384": hashlib.sha384,
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5
    }

    if hash_algorithm not in hash_functions:
        raise ValueError(f"الگوریتم هش پشتیبانی نمی‌شود: {hash_algorithm}")

    hash_func = hash_functions[hash_algorithm]()

    with open(file_path, 'rb') as f:
        # خواندن فایل به صورت قطعات برای فایل‌های بزرگ
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.digest()


def sign_file(file_path):
    """
    امضای دیجیتال فایل

    Args:
        file_path: مسیر فایل اصلی
        private_key: کلید خصوصی
        output_path: مسیر فایل خروجی (اگر None باشد، پسوند .sig اضافه می‌شود)
        hash_algorithm: الگوریتم هش

    Returns:
        مسیر فایل امضا شده
    """
    output_path = file_path
    username = app_config.username
    password = app_config.password
    private_key = get_private_key(username, password)

    hash_algorithm = 'SHA256'
    if output_path is None:
        output_path = file_path + ".sig"

    # محاسبه هش فایل
    file_hash = calculate_file_hash(file_path, hash_algorithm)

    # امضای هش
    signature = DigitalSignature.sign_data(file_hash, private_key)

    # خواندن محتوای اصلی فایل
    with open(file_path, 'rb') as f:
        original_content = f.read()

    # ساخت هدر امضا
    signature_header = {
        'algorithm': 'RSA-PSS',
        'hash_algorithm': hash_algorithm,
        'signed_by': username,
        'timestamp': os.path.getmtime(file_path),
        'file_size': len(original_content),
        'signature_length': len(signature)
    }

    # کدگذاری هدر
    header_json = json.dumps(signature_header).encode('utf-8')

    # نوشتن فایل امضا شده
    with open(output_path, 'wb') as f:
        # f.write(header_length)
        f.write(header_json)
        # جداکننده امضا
        f.write(b'---SIGNATURE_SEPARATOR---')
        # امضا
        f.write(signature)
        # جداکننده محتوا
        f.write(b'---CONTENT_SEPARATOR---')
        # محتوای اصلی فایل
        f.write(original_content)

    with open(file_path, 'rb') as f:
        original_content = f.read()
        print(f'f_after_sign:{original_content}')
    return output_path


def verify_file_signature(signed_file_path):

    with open(signed_file_path, 'rb') as f:
        full_data = f.read()
    header = get_file_header(signed_file_path)
    signature_separator = b'---SIGNATURE_SEPARATOR---'
    separator_pos = full_data.find(signature_separator)
    if separator_pos == -1:
        raise ValueError("جداکننده امضا پیدا نشد")

    signature_start = separator_pos + len(signature_separator)
    content_separator = b'---CONTENT_SEPARATOR---'
    content_separator_pos = full_data.find(content_separator, signature_start)

    if content_separator_pos == -1:
        raise ValueError("جداکننده محتوا پیدا نشد")

    signature_data = full_data[signature_start:content_separator_pos]
    original_content = full_data[content_separator_pos + len(content_separator):]
    signature_info = header
    public_key = get_public_key(signature_info['signed_by'])
        # # خواندن طول هدر
        # header_length_bytes = f.read(4)
        # if len(header_length_bytes) < 4:
        #     raise ValueError("فایل معتبر نیست: طول هدر موجود نیست")
        # header_length = int.from_bytes(header_length_bytes, byteorder='big')
        #
        # # خواندن هدر
        # header_bytes = f.read(header_length)
        # if len(header_bytes) < header_length:
        #     raise ValueError("فایل معتبر نیست: هدر کامل نیست")
        #
        # # تبدیل هدر به دیکشنری
        # try:
        #     signature_info = eval(header_bytes.decode('utf-8'))
        # except:
        #     raise ValueError("فایل معتبر نیست: هدر قابل خواندن نیست")
        #
        # # پیدا کردن جداکننده امضا
        # signature_separator = b'---SIGNATURE_SEPARATOR---'
        # separator_pos = header_bytes.find(signature_separator)
        #
        # if separator_pos == -1:
        #     # جستجو در ادامه فایل
        #     remaining_data = f.read()
        #     full_data = header_bytes + remaining_data
        #     separator_pos = full_data.find(signature_separator)
        #
        #     if separator_pos == -1:
        #         raise ValueError("جداکننده امضا پیدا نشد")
        #
        #     signature_start = separator_pos + len(signature_separator)
        #     content_separator = b'---CONTENT_SEPARATOR---'
        #     content_separator_pos = full_data.find(content_separator, signature_start)
        #
        #     if content_separator_pos == -1:
        #         raise ValueError("جداکننده محتوا پیدا نشد")
        #
        #     signature_data = full_data[signature_start:content_separator_pos]
        #     original_content = full_data[content_separator_pos + len(content_separator):]
        #
        # else:
        #     # خواندن امضا
        #     signature_data = f.read(signature_info['signature_length'])
        #
        #     # پیدا کردن جداکننده محتوا
        #     content_separator = b'---CONTENT_SEPARATOR---'
        #     separator_data = f.read(len(content_separator))
        #
        #     if separator_data != content_separator:
        #         raise ValueError("جداکننده محتوا پیدا نشد")
        #
        #     # خواندن محتوای اصلی
        #     original_content = f.read()

    # محاسبه مجدد هش
    recalculated_hash = calculate_file_hash_from_content(original_content, signature_info['hash_algorithm'])

    # بررسی امضا
    is_valid = DigitalSignature.verify_signature(recalculated_hash, signature_data, public_key)

    result = {
        'is_valid': is_valid,
        'algorithm': signature_info['algorithm'],
        'hash_algorithm': signature_info['hash_algorithm'],
        'file_size': signature_info['file_size'],
        'signature_length': signature_info['signature_length']
    }

    if is_valid:
        result['original_content'] = original_content

    return result


def calculate_file_hash_from_content(content: bytes, hash_algorithm: str = "SHA256") -> bytes:
    """
    محاسبه هش از محتوای داده

    Args:
        content: محتوای داده
        hash_algorithm: الگوریتم هش

    Returns:
        هش محاسبه شده
    """
    hash_functions = {
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
        "SHA384": hashlib.sha384,
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5
    }

    if hash_algorithm not in hash_functions:
        raise ValueError(f"الگوریتم هش پشتیبانی نمی‌شود: {hash_algorithm}")

    hash_func = hash_functions[hash_algorithm]()
    hash_func.update(content)
    return hash_func.digest()


def save_private_key(private_key, file_path: str, password: bytes = None):
    """
    ذخیره کلید خصوصی در فایل

    Args:
        private_key: کلید خصوصی
        file_path: مسیر فایل
        password: رمز برای رمزنگاری کلید (اختیاری)
    """
    from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, BestAvailableEncryption, \
        NoEncryption

    if password:
        encryption_algorithm = BestAvailableEncryption(password)
    else:
        encryption_algorithm = NoEncryption()

    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    with open(file_path, 'wb') as f:
        f.write(pem)


def save_public_key(public_key, file_path: str):
    """
    ذخیره کلید عمومی در فایل

    Args:
        public_key: کلید عمومی
        file_path: مسیر فایل
    """
    from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding

    pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    with open(file_path, 'wb') as f:
        f.write(pem)


def load_private_key(file_path: str, password: bytes = None):
    """
    بارگذاری کلید خصوصی از فایل

    Args:
        file_path: مسیر فایل
        password: رمز برای رمزگشایی کلید (اگر رمزگذاری شده باشد)

    Returns:
        کلید خصوصی
    """
    with open(file_path, 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=password)
    return private_key


def load_public_key(file_path: str):
    """
    بارگذاری کلید عمومی از فایل

    Args:
        file_path: مسیر فایل

    Returns:
        کلید عمومی
    """
    with open(file_path, 'rb') as f:
        public_key = load_pem_public_key(f.read())
    return public_key


# مثال استفاده با کلیدهای دلخواه
# if __name__ == "__main__":
#     # تولید کلیدها (مثال - شما می‌توانید کلیدهای خود را از فایل بارگذاری کنید)
#     private_key, public_key = DigitalSignature.generate_key_pair()
#
#     # فایل نمونه
#     test_file = "test_document.txt"
#
#     # ایجاد فایل تست
#     with open(test_file, 'w', encoding='utf-8') as f:
#         f.write("این یک سند تست برای امضای دیجیتال است.\n")
#         f.write("محتوا باید بدون تغییر باقی بماند.")
#
#     print("=== امضای فایل ===")
#     signed_file = sign_file(test_file, private_key, "signed_document.sig")
#     print(f"فایل امضا شده ایجاد شد: {signed_file}")
#
#     print("\n=== بررسی امضا ===")
#     verification = verify_file_signature(signed_file, public_key)
#     print(f"امضا معتبر است: {verification['is_valid']}")
#
#     if verification['is_valid']:
#         print(f"الگوریتم: {verification['algorithm']}")
#         print(f"الگوریتم هش: {verification['hash_algorithm']}")
#         print(f"اندازه فایل: {verification['file_size']} بایت")
#
#         # نمایش محتوای اصلی
#         content = verification['original_content'].decode('utf-8')
#         print(f"\nمحتوای اصلی:\n{content}")
#
#     print("\n=== تست تغییر فایل ===")
#     # تغییر فایل اصلی
#     with open(test_file, 'a', encoding='utf-8') as f:
#         f.write("\nاین خط بعداً اضافه شد!")
#
#     # بررسی مجدد امضا (باید نامعتبر شود)
#     verification_modified = verify_file_signature(signed_file, public_key)
#     print(f"امضا پس از تغییر فایل معتبر است: {verification_modified['is_valid']}")
#
#     print("\n=== استفاده از کلیدهای دلخواه ===")
#     # مثال بارگذاری کلیدهای دلخواه
#     try:
#         # ذخیره کلیدها در فایل (برای مثال)
#         save_private_key(private_key, "my_private_key.pem")
#         save_public_key(public_key, "my_public_key.pem")
#
#         # بارگذاری کلیدهای دلخواه
#         my_private_key = load_private_key("my_private_key.pem")
#         my_public_key = load_public_key("my_public_key.pem")
#
#         print("کلیدهای دلخواه با موفقیت بارگذاری شدند")
#
#         # استفاده از کلیدهای دلخواه برای امضا
#         custom_signed_file = sign_file(test_file, my_private_key, "custom_signed.sig")
#         print(f"فایل با کلید دلخواه امضا شد: {custom_signed_file}")
#
#         # بررسی با کلید دلخواه
#         custom_verification = verify_file_signature(custom_signed_file, my_public_key)
#         print(f"امضا با کلید دلخواه معتبر است: {custom_verification['is_valid']}")
#
#     except Exception as e:
#         print(f"خطا در کار با کلیدهای دلخواه: {e}")
