import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import json
from set_user import app_config
from utilities import get_private_key, get_public_key
from utilities import get_file_header
from cryptography.hazmat.primitives.serialization import PrivateFormat, Encoding, BestAvailableEncryption, NoEncryption
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key



class DigitalSignature:
    """ Create and check signatures """

    @staticmethod
    def sign_data(data: bytes, private_key) -> bytes:

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

    hash_functions = {
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
        "SHA384": hashlib.sha384,
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5
    }

    if hash_algorithm not in hash_functions:
        raise ValueError(f"{hash_algorithm} Algorithm not supported.")

    hash_func = hash_functions[hash_algorithm]()

    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)

    return hash_func.digest()


def sign_file(file_path):

    output_path = file_path
    username = app_config.username
    password = app_config.password
    private_key = get_private_key(username, password)

    hash_algorithm = 'SHA256'
    if output_path is None:
        output_path = file_path + ".sig"

    file_hash = calculate_file_hash(file_path, hash_algorithm)

    signature = DigitalSignature.sign_data(file_hash, private_key)

    with open(file_path, 'rb') as f:
        original_content = f.read()

    signature_header = {
        'algorithm': 'RSA-PSS',
        'hash_algorithm': hash_algorithm,
        'signed_by': username,
        'timestamp': os.path.getmtime(file_path),
        'file_size': len(original_content),
        'signature_length': len(signature)
    }

    header_json = json.dumps(signature_header).encode('utf-8')

    with open(output_path, 'wb') as f:
        f.write(header_json)
        f.write(b'---SIGNATURE_SEPARATOR---')
        f.write(signature)
        f.write(b'---CONTENT_SEPARATOR---')
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
        raise ValueError("Signature Separator not found")

    signature_start = separator_pos + len(signature_separator)
    content_separator = b'---CONTENT_SEPARATOR---'
    content_separator_pos = full_data.find(content_separator, signature_start)

    if content_separator_pos == -1:
        raise ValueError("Content Separator not found")

    signature_data = full_data[signature_start:content_separator_pos]
    original_content = full_data[content_separator_pos + len(content_separator):]
    signature_info = header
    public_key = get_public_key(signature_info['signed_by'])

    recalculated_hash = calculate_file_hash_from_content(original_content, signature_info['hash_algorithm'])
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

    hash_functions = {
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
        "SHA384": hashlib.sha384,
        "SHA1": hashlib.sha1,
        "MD5": hashlib.md5
    }

    if hash_algorithm not in hash_functions:
        raise ValueError(f"{hash_algorithm} Algorithm not supported.")

    hash_func = hash_functions[hash_algorithm]()
    hash_func.update(content)
    return hash_func.digest()


# def save_private_key(private_key, file_path: str, password: bytes = None):
#
#     if password:
#         encryption_algorithm = BestAvailableEncryption(password)
#     else:
#         encryption_algorithm = NoEncryption()
#
#     pem = private_key.private_bytes(
#         encoding=Encoding.PEM,
#         format=PrivateFormat.PKCS8,
#         encryption_algorithm=encryption_algorithm
#     )
#     with open(file_path, 'wb') as f:
#         f.write(pem)
#
#
# def save_public_key(public_key, file_path: str):
#
#     pem = public_key.public_bytes(
#         encoding=Encoding.PEM,
#         format=PublicFormat.SubjectPublicKeyInfo
#     )
#     with open(file_path, 'wb') as f:
#         f.write(pem)
#
#
# def load_private_key(file_path: str, password: bytes = None):
#
#     with open(file_path, 'rb') as f:
#         private_key = load_pem_private_key(f.read(), password=password)
#     return private_key
#
#
# def load_public_key(file_path: str):
#
#     with open(file_path, 'rb') as f:
#         public_key = load_pem_public_key(f.read())
#     return public_key

