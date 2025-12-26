import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC

def generate_mac(data: bytes, key: bytes, mode: str) -> bytes:
    """Generates MAC value using chosen mode."""
    if mode == "HMAC":
        return hmac.new(key, data, hashlib.sha256).digest()
    elif mode == "OMAC":
        mac = CMAC.new(key, ciphermod=AES)
        mac.update(data)
        return mac.digest()
    elif mode == "CCM":
        nonce = get_random_bytes(11)
        cipher = AES.new(key, AES.MODE_CCM, nonce=nonce)
        cipher.update(data)
        _, tag = cipher.encrypt_and_digest(b"")
        return nonce + tag
    else:
        raise ValueError("Invalid MAC mode")

def verify_mac(data: bytes, key: bytes, mode: str, mac_value: bytes) -> bool:
    """Verifies MAC correctness."""
    new_mac = generate_mac(data, key, mode)
    return hmac.compare_digest(new_mac, mac_value)
