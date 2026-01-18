import os
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes, cmac
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from utilities import get_file_header
import json

class MACCalculator:
    """کلاس اصلی برای محاسبه MAC با الگوریتم‌های OMAC, CCM, HMAC"""

    @staticmethod
    def calculate_hmac(data: bytes, key: bytes, hash_algorithm: str = "SHA256") -> bytes:
        """
        محاسبه HMAC با الگوریتم هش مشخص

        Args:
            data: داده ورودی
            key: کلید HMAC
            hash_algorithm: الگوریتم هش (SHA256, SHA512, SHA384, SHA224, SHA1, MD5)

        Returns:
            MAC محاسبه شده
        """
        hash_functions = {
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
            "SHA384": hashlib.sha384,
            "SHA224": hashlib.sha224,
            "SHA1": hashlib.sha1,
            "MD5": hashlib.md5
        }

        if hash_algorithm not in hash_functions:
            raise ValueError(f"الگوریتم هش پشتیبانی نمی‌شود: {hash_algorithm}")

        return hmac.new(key, data, hash_functions[hash_algorithm]).digest()

    @staticmethod
    def calculate_omac(data: bytes, key: bytes, algorithm: str = "AES") -> bytes:
        """
        محاسبه OMAC (One-Key CBC MAC) یا CMAC

        Args:
            data: داده ورودی
            key: کلید رمزنگاری
            algorithm: الگوریتم (AES)

        Returns:
            MAC محاسبه شده
        """
        if algorithm.upper() != "AES":
            raise ValueError("فقط AES برای OMAC پشتیبانی می‌شود")

        # بررسی طول کلید
        if len(key) not in [16, 24, 32]:
            raise ValueError("کلید AES باید 16, 24 یا 32 بایت باشد")

        # استفاده از CMAC که همان OMAC1 است
        c = cmac.CMAC(algorithms.AES(key), backend=default_backend())
        c.update(data)
        return c.finalize()

    @staticmethod
    def calculate_ccm(data: bytes, key: bytes, nonce: bytes = None, associated_data: bytes = b"") -> tuple:
        """
        محاسبه CCM (Counter with CBC-MAC)

        Args:
            data: داده ورودی
            key: کلید رمزنگاری
            nonce: مقدار یکبارمصرف (اگر None باشد، به صورت تصادفی تولید می‌شود)
            associated_data: داده همراه (اختیاری)

        Returns:
            tuple: (ciphertext, tag, nonce)
        """
        # بررسی طول کلید
        if len(key) not in [16, 24, 32]:
            raise ValueError("کلید AES باید 16, 24 یا 32 بایت باشد")

        # تولید nonce اگر ارائه نشده باشد
        if nonce is None:
            nonce = os.urandom(13)  # طول معمول nonce برای CCM

        # ایجاد cipher CCM
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # اضافه کردن داده همراه (اگر وجود دارد)
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        # رمزنگاری و تولید tag
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag

        return ciphertext, tag, nonce

    @staticmethod
    def verify_ccm(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:
        """
        بررسی و رمزگشایی CCM

        Args:
            ciphertext: متن رمز شده
            tag: تگ احراز هویت
            key: کلید رمزنگاری
            nonce: مقدار یکبارمصرف
            associated_data: داده همراه (اختیاری)

        Returns:
            داده اصلی رمزگشایی شده

        Raises:
            InvalidTag: اگر تگ معتبر نباشد
        """
        # بررسی طول کلید
        if len(key) not in [16, 24, 32]:
            raise ValueError("کلید AES باید 16, 24 یا 32 بایت باشد")

        # ایجاد cipher CCM برای رمزگشایی
        algorithm = algorithms.AES(key)
        cipher = Cipher(algorithm, modes.CCM(nonce, tag=tag), backend=default_backend())
        decryptor = cipher.decryptor()

        # اضافه کردن داده همراه (اگر وجود دارد)
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        # رمزگشایی و بررسی تگ
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise InvalidTag("تگ CCM معتبر نیست")


def calculate_file_mac(file_path: str, mac_algorithm: str, key: bytes, **kwargs) -> dict:
    """
    محاسبه MAC برای فایل با الگوریتم مشخص

    Args:
        file_path: مسیر فایل
        mac_algorithm: الگوریتم MAC (OMAC, CCM, HMAC)
        key: کلید
        **kwargs: پارامترهای اضافی

    Returns:
        دیکشنری حاوی نتایج MAC
    """
    # خواندن محتوای فایل
    with open(file_path, 'rb') as f:
        file_data = f.read()

    result = {
        'algorithm': mac_algorithm,
        'file_size': len(file_data),
        'file_path': file_path
    }

    if mac_algorithm.upper() == "HMAC":
        hash_algo = kwargs.get('hash_algorithm', 'SHA256')
        mac_value = MACCalculator.calculate_hmac(file_data, key, hash_algo)
        result.update({
            'mac_value': mac_value,
            'hash_algorithm': hash_algo,
            'mac_length': len(mac_value)
        })

    elif mac_algorithm.upper() == "OMAC":
        algo = kwargs.get('algorithm', 'AES')
        mac_value = MACCalculator.calculate_omac(file_data, key, algo)
        result.update({
            'mac_value': mac_value,
            'cipher_algorithm': algo,
            'mac_length': len(mac_value)
        })

    elif mac_algorithm.upper() == "CCM":
        nonce = kwargs.get('nonce')
        associated_data = kwargs.get('associated_data', b"")
        ciphertext, tag, used_nonce = MACCalculator.calculate_ccm(file_data, key, nonce, associated_data)
        result.update({
            'ciphertext': ciphertext,
            'tag': tag,
            'nonce': used_nonce,
            'associated_data': associated_data,
            'mac_length': len(tag)
        })

    else:
        raise ValueError(f"الگوریتم MAC پشتیبانی نمی‌شود: {mac_algorithm}")
    print(f'result------197: {result}')
    return result


def embed_mac_in_file(file_path: str, mac_algorithm: str, key: bytes, output_path: str = None, **kwargs) -> str:
    """
    محاسبه MAC و قرار دادن آن در فایل (بدون تغییر پسوند)

    Args:
        file_path: مسیر فایل اصلی
        mac_algorithm: الگوریتم MAC
        key: کلید
        output_path: مسیر خروجی (اگر None باشد، روی فایل اصلی بازنویسی می‌شود)
        **kwargs: پارامترهای اضافی

    Returns:
        مسیر فایل خروجی
    """
    if output_path is None:
        output_path = file_path

    # محاسبه MAC
    mac_result = calculate_file_mac(file_path, mac_algorithm, key, **kwargs)

    # خواندن محتوای اصلی فایل
    with open(file_path, 'rb') as f:
        original_content = f.read()

    # ساخت هدر MAC
    mac_header = {
        'mac_algorithm': mac_algorithm,
        'timestamp': os.path.getmtime(file_path),
        'file_size': len(original_content)
    }

    # اضافه کردن اطلاعات خاص الگوریتم
    if mac_algorithm.upper() == "HMAC":
        mac_header.update({
            'hash_algorithm': mac_result['hash_algorithm'],
            'mac_value': mac_result['mac_value'].hex(),
            'mac_length': mac_result['mac_length']
        })
        mac_data = mac_result['mac_value']

    elif mac_algorithm.upper() == "OMAC":
        mac_header.update({
            'cipher_algorithm': mac_result['cipher_algorithm'],
            'mac_value': mac_result['mac_value'].hex(),
            'mac_length': mac_result['mac_length']
        })
        mac_data = mac_result['mac_value']

    elif mac_algorithm.upper() == "CCM":
        mac_header.update({
            'nonce': mac_result['nonce'].hex(),
            'tag': mac_result['tag'].hex(),
            'associated_data': mac_result['associated_data'].hex(),
            'mac_length': mac_result['mac_length'],
            'ciphertext_length': len(mac_result['ciphertext'])
        })
        mac_data = mac_result['tag'] + mac_result['nonce'] + mac_result['ciphertext']

    # کدگذاری هدر
    header_json = json.dumps(mac_header).encode('utf-8')
    header_length = len(header_json).to_bytes(4, byteorder='big')

    # نوشتن فایل جدید با MAC
    with open(output_path, 'wb') as f:
        # f.write(header_length)
        f.write(header_json)
        # جداکننده MAC
        f.write(b'---MAC_SEPARATOR---')

        if mac_algorithm.upper() == "CCM":
            # برای CCM: تگ + nonce + ciphertext
            f.write(mac_data)
        else:
            # برای HMAC و OMAC: فقط مقدار MAC
            f.write(mac_data)

        # جداکننده محتوا
        f.write(b'---CONTENT_SEPARATOR---')

        if mac_algorithm.upper() == "CCM":
            # برای CCM: داده اصلی رمز شده است
            f.write(mac_result['ciphertext'])
        else:
            # برای HMAC و OMAC: محتوای اصلی فایل
            f.write(original_content)
    with open(file_path, 'rb') as f:
        original_content = f.read()
        print(f'f_after_mac:{original_content}')
    return output_path


def extract_and_verify_mac(file_path: str, key: bytes, **kwargs) -> dict:

    with open(file_path, 'rb') as f:
        # خواندن کل فایل
        full_data = f.read()

    # تحلیل هدر (فرض می‌کنیم header قبلاً استخراج شده)
    header = get_file_header(file_path)  # این باید یک دیکشنری باشد
    print("Header:", header)

    # جداکننده‌ها
    content_separator = b'---CONTENT_SEPARATOR---'
    mac_separator = b'---MAC_SEPARATOR---'

    # پیدا کردن موقعیت `mac_separator`
    mac_separator_pos = full_data.find(mac_separator)
    if mac_separator_pos == -1:
        raise ValueError("جداکننده MAC یافت نشد")

    # شروع بخش MAC (بعد از ---MAC_SEPARATOR---)
    mac_start = mac_separator_pos

    # پیدا کردن موقعیت اولین ---CONTENT_SEPARATOR--- بعد از mac_start
    content_separator_pos = full_data.find(content_separator)
    if content_separator_pos == -1:
        raise ValueError("جداکننده محتوا یافت نشد")
    content_separator_pos = content_separator_pos + len(content_separator)
    # استخراج داده MAC (بین mac_separator و content_separator)
    print(f'content_separator_pos:{content_separator_pos}, mac_start:{mac_start}, pose_pose: {full_data[content_separator_pos:mac_start]}')
    mac_data = full_data[content_separator_pos:mac_start]

    # تبدیل به رشته و تجزیه JSON
    try:
        mac_info_string = mac_data.decode('utf-8')
        mac_dictionary = json.loads(mac_data)
        print("دیکشنری MAC با موفقیت استخراج شد:", mac_dictionary)
    except Exception as e:
        print(f"خطا در تجزیه MAC: {e}")
        raise

    mac_info = mac_dictionary
    mac_data = mac_info['mac_length']
    print(f'mac_data: {mac_data}')

    if mac_info['mac_algorithm'].upper() == "CCM":
        mac_data += len(mac_info['nonce']) // 2  # nonce (hex to bytes)
        mac_data += mac_info['ciphertext_length']


    separator_data = full_data.find(content_separator, mac_start)

    if full_data[separator_data:separator_data+len(content_separator)] != content_separator:
        raise ValueError("جداکننده محتوا پیدا نشد")

    original_content = full_data[separator_data+len(content_separator):len(full_data)]
    print(f'original_content:{original_content}')
    mac_length = mac_info['mac_length']
    raw_mac_and_content_block = full_data[mac_separator_pos + len(mac_separator): separator_data]
    print(f'raw_mac_and_content_block:{raw_mac_and_content_block}')
    actual_mac_bytes = raw_mac_and_content_block[:mac_length]
    encrypted_content = ''
    # خواندن محتوای اصلی/رمز شده
    # if mac_info['mac_algorithm'].upper() == "CCM":
    #     encrypted_content = f.read()
    # else:
    #     original_content = f.read()

    # بررسی MAC بر اساس الگوریتم
    result = {
        'algorithm': mac_info['mac_algorithm'],
        'is_valid': False,
        'mac_info': mac_info
    }

    try:
        if mac_info['mac_algorithm'].upper() == "HMAC":
            # استخراج MAC از داده
            extracted_mac = actual_mac_bytes

            # محاسبه مجدد MAC
            calculated_mac = MACCalculator.calculate_hmac(
                original_content,
                key,
                mac_info['hash_algorithm']
            )

            result['is_valid'] = extracted_mac == calculated_mac
            result['extracted_mac'] = extracted_mac
            result['calculated_mac'] = calculated_mac
            result['original_content'] = original_content

        elif mac_info['mac_algorithm'].upper() == "OMAC":
            # استخراج MAC از داده
            extracted_mac = actual_mac_bytes

            # محاسبه مجدد MAC
            calculated_mac = MACCalculator.calculate_omac(
                original_content,
                key,
                mac_info['cipher_algorithm']
            )

            result['is_valid'] = extracted_mac == calculated_mac
            result['extracted_mac'] = extracted_mac
            result['calculated_mac'] = calculated_mac
            result['original_content'] = original_content

        elif mac_info['mac_algorithm'].upper() == "CCM":
            # استخراج اجزای CCM
            tag = bytes.fromhex(mac_info['tag'])
            nonce = bytes.fromhex(mac_info['nonce'])
            associated_data = bytes.fromhex(mac_info['associated_data'])

            # رمزگشایی و بررسی
            try:
                decrypted_content = MACCalculator.verify_ccm(
                    encrypted_content,
                    tag,
                    key,
                    nonce,
                    associated_data
                )
                result['is_valid'] = True
                result['original_content'] = decrypted_content
                result['decrypted_successfully'] = True
            except InvalidTag:
                result['is_valid'] = False
                result['decrypted_successfully'] = False
                result['error'] = "تگ CCM معتبر نیست"

    except Exception as e:
        result['error'] = str(e)
        result['is_valid'] = False
    print(f'result: {result}')
    return result


# مثال استفاده
# if __name__ == "__main__":
#     # کلید نمونه
#     key = b'my-secret-key-32-bytes-long!!'
#
#     # فایل نمونه
#     test_file = "test_file.txt"
#
#     # ایجاد فایل تست
#     with open(test_file, 'w') as f:
#         f.write("This is a test file content for MAC calculation.")
#
#     print("=== تست HMAC ===")
#     hmac_result = calculate_file_mac(test_file, "HMAC", key, hash_algorithm="SHA256")
#     print(f"HMAC-SHA256: {hmac_result['mac_value'].hex()}")
#
#     print("\n=== تست OMAC ===")
#     omac_result = calculate_file_mac(test_file, "OMAC", key)
#     print(f"OMAC-AES: {omac_result['mac_value'].hex()}")
#
#     print("\n=== تست CCM ===")
#     ccm_result = calculate_file_mac(test_file, "CCM", key)
#     print(f"CCM Tag: {ccm_result['tag'].hex()}")
#     print(f"CCM Nonce: {ccm_result['nonce'].hex()}")
#
#     print("\n=== جاسازی و بررسی MAC ===")
#     # جاسازی HMAC در فایل
#     embedded_file = embed_mac_in_file(test_file, "HMAC", key, "test_with_mac.txt", hash_algorithm="SHA256")
#     print(f"فایل با MAC ایجاد شد: {embedded_file}")
#
#     # بررسی MAC
#     verification = extract_and_verify_mac(embedded_file, key)
#     print(f"MAC معتبر است: {verification['is_valid']}")
#     if verification['is_valid']:
#         print(f"محتوای اصلی: {verification['original_content'].decode('utf-8')}")