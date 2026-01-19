from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms as AES_algorithm
from cryptography.hazmat.decrepit.ciphers import algorithms
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes

# ---------------------------------------------------------------------------------------------------
# ----------------------------------Encryption-------------------------------------------------------
# ---------------------------------------------------------------------------------------------------


def RSA_encryption(data, receiver_public_key) -> bytes:
    encrypted_data = receiver_public_key.encrypt(
        data,
        rsa.padding.OAEP(
            mgf=rsa.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data


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
        raise ValueError(f"الگوریتم {algorithm} پشتیبانی نمی‌شود.")

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

    padder = padding.PKCS7(cipher_algorithm.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data




# ---------------------------------------------------------------------------------------------------
# ----------------------------------Decryption-------------------------------------------------------
# ---------------------------------------------------------------------------------------------------



def RSA_decryption(data, private_key):
    decrypt_data = private_key.decrypt(
        data,
        rsa.padding.OAEP(
            mgf=rsa.padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypt_data


def symmetric_decrypt(encrypted_data, key, algorithm, mode):

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
        raise ValueError(f"الگوریتم {algorithm} پشتیبانی نمی‌شود.")

    iv = key[:iv_length]
    encrypted_payload = encrypted_data

    cipher_mode = {
        'CBC': modes.CBC(iv),
        'CFB': modes.CFB(iv),
        'CTR': modes.CTR(iv)
    }[mode]

    if cipher_mode is None:
        raise ValueError(f"Unsupported encryption mode: {mode}")

    cipher = Cipher(cipher_algorithm, cipher_mode, backend=default_backend())
    decryptor = cipher.decryptor()


    decrypted_chunk = decryptor.update(encrypted_payload)
    final_decrypted = decryptor.finalize()
    full_decrypted = decrypted_chunk + final_decrypted

    unpadder = padding.PKCS7(cipher_algorithm.block_size).unpadder()
    decrypted_data_final = unpadder.update(full_decrypted) + unpadder.finalize()
    print(f'decrypted_data: {decrypted_data_final}')
    return decrypted_data_final

