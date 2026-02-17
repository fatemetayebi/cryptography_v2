from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------------------------------
# ---------------------------------- Encryption ----------------------------------------------------
# ---------------------------------------------------------------------------------------------------


from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes


def RSA_encryption(data, receiver_public_key) -> bytes:
    """
    Encrypt data using RSA with OAEP padding
    """
    try:
        # Calculate maximum data size for this key
        key_size_bytes = receiver_public_key.key_size // 8
        max_data_size = key_size_bytes - 66  # For OAEP with SHA256

        if len(data) > max_data_size:
            raise ValueError(
                f"Data too large for RSA encryption. "
                f"Max: {max_data_size} bytes, Actual: {len(data)} bytes"
            )

        encrypted_data = receiver_public_key.encrypt(
            data,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(f"✅ RSA encryption successful")
        print(f"📊 Input size: {len(data)} bytes")
        print(f"📊 Output size: {len(encrypted_data)} bytes")
        print(f"📊 Key size: {receiver_public_key.key_size} bits")

        return encrypted_data

    except Exception as e:
        print(f"❌ RSA encryption failed: {e}")
        raise


def symmetric_encrypt(data, key, algorithm, mode):
    algorithm = algorithm.upper()

    if algorithm == 'AES':
        iv_length = 16
        cipher_algorithm = AES_algorithm.AES(key)
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key size invalid for AES")
    elif algorithm in ('DES', '3DES'):
        iv_length = 8
        cipher_algorithm = algorithms.TripleDES(key)
        if len(key) not in [8, 16, 24]:
            raise ValueError("Key size invalid for DES/3DES")
    else:
        raise ValueError(f"{algorithm} Algorithm not supported")

    iv = key[:iv_length]

    cipher_mode = {
        'CBC': modes.CBC(iv),
        'CFB': modes.CFB(iv),
        'CTR': modes.CTR(iv)
    }[mode]

    if cipher_mode is None:
        raise ValueError(f"Unsupported encryption mode: {mode}")

    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    encryptor = cipher.encryptor()

    if mode == 'CBC':
        padder = padding.PKCS7(cipher_algorithm.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
    else:
        padded_data = data

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data


# ---------------------------------------------------------------------------------------------------
# ---------------------------------- Decryption ----------------------------------------------------
# ---------------------------------------------------------------------------------------------------



def RSA_decryption(encrypted_data, private_key):
    """
    Decrypt data using RSA with OAEP padding
    """
    try:
        expected_size = private_key.key_size // 8
        actual_size = len(encrypted_data)

        print(f"🔍 RSA Decryption Debug:")
        print(f"   Expected size: {expected_size} bytes")
        print(f"   Actual size: {actual_size} bytes")

        # Check if size matches
        if actual_size != expected_size:
            print(f"⚠️ Size mismatch! Attempting to handle...")

            if actual_size < expected_size:
                # Add padding if data is smaller
                padding_needed = expected_size - actual_size
                encrypted_data = b'\x00' * padding_needed + encrypted_data
                print(f"   Added {padding_needed} bytes of padding")
            elif actual_size > expected_size:
                # Truncate if data is larger
                encrypted_data = encrypted_data[:expected_size]
                print(f"   Trimmed data to {expected_size} bytes")

        # Decrypt the data
        decrypted_data = private_key.decrypt(
            encrypted_data,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        print(f"✅ RSA decryption successful")
        print(f"📊 Decrypted size: {len(decrypted_data)} bytes")

        return decrypted_data

    except Exception as e:
        print(f"❌ RSA decryption failed: {e}")
        print(f"   Key size: {private_key.key_size} bits")
        print(f"   Data size: {len(encrypted_data)} bytes")
        raise



def symmetric_decrypt(encrypted_data, key, algorithm, mode):

    algorithm = algorithm.upper()

    if algorithm == 'AES':
        iv_length = 16
        cipher_algorithm = AES_algorithm.AES(key)  # Using cryptography library
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key size invalid for AES")
    elif algorithm in ('DES', '3DES'):
        iv_length = 8
        cipher_algorithm = algorithms.TripleDES(key)
        if len(key) not in [8, 16, 24]:
            raise ValueError("Key size invalid for DES/3DES")
    else:
        raise ValueError(f"{algorithm} Algorithm not supported")

    # Using IV from the beginning of the key
    iv = key[:iv_length]

    # Selecting mode
    if mode == 'CBC':
        cipher_mode = modes.CBC(iv)
    elif mode == 'CFB':
        cipher_mode = modes.CFB(iv)
    elif mode == 'CTR':
        cipher_mode = modes.CTR(iv)
    else:
        raise ValueError(f"Unsupported encryption mode: {mode}")

    # Creating cipher and decryptor
    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()

    # Decryption
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # If CBC mode, perform unpadding
    if mode == 'CBC':
        unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data
