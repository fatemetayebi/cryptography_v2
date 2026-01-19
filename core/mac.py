import hashlib
import hmac
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms as AES_Algo
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.backends import default_backend
import os
from cryptography.exceptions import InvalidTag
from utilities import get_file_header
import json

class MACCalculator:
    """ Main class for calculating mac """

    @staticmethod
    def calculate_hmac(data: bytes, key: bytes, hash_algorithm: str = "SHA256") -> bytes:

        hash_functions = {
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512,
            "SHA384": hashlib.sha384,
            "SHA224": hashlib.sha224,
            "SHA1": hashlib.sha1,
            "MD5": hashlib.md5
        }

        if hash_algorithm not in hash_functions:
            raise ValueError(f" {hash_algorithm} hash algorithm not supported.")

        return hmac.new(key, data, hash_functions[hash_algorithm]).digest()


    @staticmethod
    def calculate_omac(data: bytes, key: bytes, algorithm: str = "AES") -> bytes:

        if algorithm.upper() != "AES":
            raise ValueError("Just the AES algorithm support.")

        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key size must be 16, 24, or 32 bytes.")

        c = cmac.CMAC(AES_Algo.AES(key), backend=default_backend())
        c.update(data)
        return c.finalize()

    @staticmethod
    def calculate_ccm(data: bytes, key: bytes, nonce: bytes = None, associated_data: bytes = b"") -> tuple[
        bytes, bytes, bytes]:

        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key size must be 16, 24, or 32 bytes.")

        if nonce is None:
            nonce = os.urandom(12)

        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long.")

        aes_ccm = AESCCM(key)


        try:
            ciphertext_with_tag = aes_ccm.encrypt(
                nonce,
                data,
                associated_data
            )
        except Exception as e:
            raise RuntimeError(f" Calculate ccm went wrong: {e}")


        tag_length = 16
        aes_ccm = AESCCM(key, tag_length)

        ciphertext_with_tag = aes_ccm.encrypt(nonce, data, associated_data)

        try:
            ciphertext, tag = aes_ccm.encrypt_and_extract_tag(nonce, data, associated_data)
            return ciphertext, tag, nonce
        except AttributeError:

            tag_length = 16
            ciphertext = ciphertext_with_tag[:-tag_length]
            tag = ciphertext_with_tag[-tag_length:]
            return ciphertext, tag, nonce


    @staticmethod
    def verify_ccm(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:

        if len(key) not in [16, 24, 32]:
            raise ValueError("AES key size must be 16, 24, or 32 bytes.")

        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long.")

        aes_ccm = AESCCM(key, tag_length=16)
        try:
            plaintext = aes_ccm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except InvalidTag:
            raise InvalidTag("CCM tag is invalid.")


def calculate_file_mac(file_path: str, mac_algorithm: str, key: bytes, **kwargs) -> dict:

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
        raise ValueError(f" MAC algorithm not support {mac_algorithm}")
    print(f'result------197: {result}')
    return result


def embed_mac_in_file(file_path: str, mac_algorithm: str, key: bytes, output_path: str = None, **kwargs) -> str:

    if output_path is None:
        output_path = file_path

    mac_result = calculate_file_mac(file_path, mac_algorithm, key, **kwargs)

    with open(file_path, 'rb') as f:
        original_content = f.read()

    mac_header = {
        'mac_algorithm': mac_algorithm,
        'timestamp': os.path.getmtime(file_path),
        'file_size': len(original_content)
    }

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
        mac_data = mac_result['ciphertext'] + mac_result['tag']

    header_json = json.dumps(mac_header).encode('utf-8')

    with open(output_path, 'wb') as f:
        f.write(header_json)
        f.write(b'---MAC_SEPARATOR---')
        f.write(mac_data)
        f.write(b'---CONTENT_SEPARATOR---')

        if mac_algorithm.upper() == "CCM":
            f.write(mac_result['ciphertext'])
        else:
            f.write(original_content)

    with open(file_path, 'rb') as f:
        original_content = f.read()
        print(f'f_after_mac:{original_content}')
    return output_path


def extract_and_verify_mac(file_path: str, key: bytes, **kwargs) -> dict:

    with open(file_path, 'rb') as f:
        full_data = f.read()

    header = get_file_header(file_path)

    content_separator = b'---CONTENT_SEPARATOR---'
    mac_separator = b'---MAC_SEPARATOR---'

    mac_separator_pos = full_data.find(mac_separator)
    if mac_separator_pos == -1:
        raise ValueError("MAC separator not found.")
    mac_start = mac_separator_pos
    content_separator_pos = full_data.find(content_separator)
    if content_separator_pos == -1:
        raise ValueError("Content separator not found.")
    content_separator_pos = content_separator_pos + len(content_separator)

    print(f'content_separator_pos:{content_separator_pos}, mac_start:{mac_start}, pose_pose: {full_data[content_separator_pos:mac_start]}')
    mac_data = full_data[content_separator_pos:mac_start]

    try:
        mac_dictionary = json.loads(mac_data)
        print("MAC dictionary extract successfully", mac_dictionary)
    except Exception as e:
        print(f"Error in extract mac{e}")
        raise

    mac_info = mac_dictionary
    mac_data = mac_info['mac_length']
    print(f'mac_data: {mac_data}')
    separator_data = full_data.find(content_separator, mac_start)

    if mac_info['mac_algorithm'].upper() == "CCM":
        mac_data += len(mac_info['nonce']) // 2  # nonce (hex to bytes)
        mac_data += mac_info['ciphertext_length']


    if full_data[separator_data:separator_data+len(content_separator)] != content_separator:
        raise ValueError("Content separator not found.")

    original_content = full_data[separator_data+len(content_separator):len(full_data)]
    print(f'original_content:{original_content}')
    mac_length = mac_info['mac_length']
    raw_mac_and_content_block = full_data[mac_separator_pos + len(mac_separator): separator_data]
    print(f'raw_mac_and_content_block:{raw_mac_and_content_block}')
    actual_mac_bytes = raw_mac_and_content_block[:mac_length]


    result = {
        'algorithm': mac_info['mac_algorithm'],
        'is_valid': False,
        'mac_info': mac_info
    }

    try:
        if mac_info['mac_algorithm'].upper() == "HMAC":
            extracted_mac = actual_mac_bytes

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
            extracted_mac = actual_mac_bytes

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
            tag = bytes.fromhex(mac_info['tag'])
            nonce = bytes.fromhex(mac_info['nonce'])
            associated_data = bytes.fromhex(mac_info['associated_data'])

            try:
                encrypted_content = raw_mac_and_content_block
                print(f'encrypted_content:{encrypted_content}')
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
                result['error'] = "CCM tag is not valid"

    except Exception as e:
        result['error'] = str(e)
        result['is_valid'] = False
    print(f'result: {result}')
    return result

