from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from utils.file_utils import write_file, read_file, file_exists

def generate_rsa_keys(key_size=2048, public_key_file=None, private_key_file=None, overwrite=False):
    """
    Generates RSA key pair and saves to files.
    """
    if public_key_file is None:
        public_key_file = "public.pem"
    if private_key_file is None:
        private_key_file = "private.pem"
    if (not overwrite) and (file_exists(public_key_file) or file_exists(private_key_file)):
        raise FileExistsError("Key files already exist. Use overwrite=True to replace them.")

    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    write_file(private_key_file, private_key)
    write_file(public_key_file, public_key)
    print(f"[+] RSA keys saved to '{private_key_file}' and '{public_key_file}'")

def rsa_encrypt_text(text, public_key_file="public.pem"):
    """
    Encrypts text using RSA public key.
    """
    pub_key = RSA.import_key(read_file(public_key_file))
    cipher = PKCS1_OAEP.new(pub_key)
    # OAEP has a max message size: key_size_in_bytes - 2*hash_size - 2
    max_len = pub_key.size_in_bytes() - 2 * SHA256.digest_size - 2
    if len(text.encode()) > max_len:
        raise ValueError(f"Text too long for RSA encryption (max {max_len} bytes for this key).")
    encrypted = cipher.encrypt(text.encode())
    return encrypted

def rsa_decrypt_text(ciphertext, private_key_file="private.pem"):
    """
    Decrypts ciphertext using RSA private key.
    """
    priv_key = RSA.import_key(read_file(private_key_file))
    cipher = PKCS1_OAEP.new(priv_key)
    try:
        decrypted = cipher.decrypt(ciphertext)
        return decrypted.decode()
    except ValueError:
        raise ValueError("Decryption failed. Possibly wrong key or corrupted ciphertext.")

def rsa_encrypt_file(filepath, public_key_file="public.pem", outpath=None, overwrite=False):
    """
    Encrypts a file using RSA public key (chunked).
    """
    pub_key = RSA.import_key(read_file(public_key_file))
    cipher = PKCS1_OAEP.new(pub_key)
    max_len = pub_key.size_in_bytes() - 2 * SHA256.digest_size - 2
    data = read_file(filepath, mode='rb')
    encrypted_chunks = []
    for i in range(0, len(data), max_len):
        chunk = data[i:i+max_len]
        encrypted_chunks.append(cipher.encrypt(chunk))
    encrypted = b"".join(encrypted_chunks)
    if outpath is None:
        outpath = filepath + ".rsa"
    if file_exists(outpath) and not overwrite:
        raise FileExistsError(f"Output file '{outpath}' already exists. Use overwrite=True to replace.")
    write_file(outpath, encrypted)
    return outpath

def rsa_decrypt_file(filepath, private_key_file="private.pem", outpath=None, overwrite=False):
    """
    Decrypts a file using RSA private key (chunked).
    """
    priv_key = RSA.import_key(read_file(private_key_file))
    cipher = PKCS1_OAEP.new(priv_key)
    key_size = priv_key.size_in_bytes()
    data = read_file(filepath, mode='rb')
    decrypted_chunks = []
    for i in range(0, len(data), key_size):
        chunk = data[i:i+key_size]
        try:
            decrypted_chunks.append(cipher.decrypt(chunk))
        except ValueError:
            raise ValueError("Decryption failed. Possibly wrong key or corrupted ciphertext.")
    decrypted = b"".join(decrypted_chunks)
    if outpath is None:
        if filepath.endswith(".rsa"):
            outpath = filepath[:-4]
        else:
            outpath = filepath + ".decrypted"
    if file_exists(outpath) and not overwrite:
        raise FileExistsError(f"Output file '{outpath}' already exists. Use overwrite=True to replace.")
    write_file(outpath, decrypted)
    return outpath

def rsa_sign_message(message, private_key_file="private.pem"):
    """
    Signs a message with RSA private key.
    """
    key = RSA.import_key(read_file(private_key_file))
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def rsa_verify_signature(message, signature, public_key_file="public.pem"):
    """
    Verifies a message signature with RSA public key.
    """
    key = RSA.import_key(read_file(public_key_file))
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False