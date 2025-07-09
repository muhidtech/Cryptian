from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from utils.file_utils import read_file, write_file
import os

# === FERNET (AES-128 CBC + HMAC) ===

def generate_fernet_key():
    """
    Generates a secure Fernet key (32 url-safe base64-encoded bytes).
    """
    return Fernet.generate_key()

def fernet_encrypt_text(text, key):
    f = Fernet(key)
    return f.encrypt(text.encode())

def fernet_decrypt_text(token, key):
    f = Fernet(key)
    try:
        return f.decrypt(token).decode()
    except InvalidToken:
        raise ValueError("Invalid Fernet token or key.")

def fernet_encrypt_file(filepath, key, outpath=None, overwrite=False):
    data = read_file(filepath, mode='rb')
    f = Fernet(key)
    encrypted = f.encrypt(data)
    if outpath is None:
        outpath = filepath + ".enc"
    if os.path.exists(outpath) and not overwrite:
        raise FileExistsError(f"Output file '{outpath}' already exists. Use overwrite=True to replace.")
    write_file(outpath, encrypted)
    return outpath

def fernet_decrypt_file(filepath, key, outpath=None, overwrite=False):
    data = read_file(filepath, mode='rb')
    f = Fernet(key)
    try:
        decrypted = f.decrypt(data)
    except InvalidToken:
        raise ValueError("Invalid Fernet token or key.")
    if outpath is None:
        if filepath.endswith(".enc"):
            outpath = filepath[:-4]
        else:
            outpath = filepath + ".decrypted"
    if os.path.exists(outpath) and not overwrite:
        store_dir = os.path.join(os.path.dirname(outpath), "store")
        os.makedirs(store_dir, exist_ok=True)
        outpath = os.path.join(store_dir, os.path.basename(outpath))
    write_file(outpath, decrypted)
    return outpath

# === AES-CBC (manual key/IV) ===

def aes_encrypt_text(text, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
    return ciphertext

def aes_decrypt_text(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

def aes_encrypt_file(filepath, key, iv, outpath=None, overwrite=False):
    data = read_file(filepath, mode='rb')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    outpath = outpath or (filepath + ".aes")
    if os.path.exists(outpath) and not overwrite:
        raise Exception(f"Output file '{outpath}' already exists. Use overwrite=True to replace.")
    write_file(outpath, cipher.encrypt(padded))
    return outpath

def aes_decrypt_file(filepath, key, iv, outpath=None, overwrite=False):
    data = read_file(filepath, mode='rb')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    try:
        unpadded = unpad(decrypted, AES.block_size)
    except ValueError:
        raise Exception("Incorrect padding. Wrong key/IV or corrupted file.")
    outpath = outpath or filepath.replace(".aes", "")
    if os.path.exists(outpath) and not overwrite:
        # Save to /store folder if exists
        store_dir = os.path.join(os.path.dirname(outpath), "store")
        os.makedirs(store_dir, exist_ok=True)
        outpath = os.path.join(store_dir, os.path.basename(outpath))
    write_file(outpath, unpadded)
    return outpath
# === Key Utilities ===

def generate_aes_key_iv(key_size=32):
    """
    Generates a random AES key and IV.
    - key_size: 16 (AES-128), 24 (AES-192), or 32 (AES-256). Default: 32 (AES-256)
    """
    key = get_random_bytes(key_size)
    iv = get_random_bytes(16)
    return key, iv

def is_valid_aes_key(key):
    """
    Checks if the key is a valid AES key length.
    """
    return len(key) in (16, 24, 32)

def is_valid_iv(iv):
    """
    Checks if the IV is a valid AES IV (16 bytes).
    """
    return len(iv) == 16