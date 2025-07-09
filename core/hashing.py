import hashlib
import bcrypt
import base64
import binascii

# === BASIC HASHING (MD5, SHA1, SHA256, SHA512, BLAKE2, etc.) ===

def hash_text(text, algo="sha256", encoding=None):
    """
    Hashes a string using the selected algorithm.
    Optionally encodes the hash output (base64, hex, urlsafe_b64, etc).
    """
    text_bytes = text.encode()

    algo = algo.lower()
    if algo == "md5":
        digest = hashlib.md5(text_bytes).digest()
    elif algo == "sha1":
        digest = hashlib.sha1(text_bytes).digest()
    elif algo == "sha256":
        digest = hashlib.sha256(text_bytes).digest()
    elif algo == "sha512":
        digest = hashlib.sha512(text_bytes).digest()
    elif algo == "blake2b":
        digest = hashlib.blake2b(text_bytes).digest()
    elif algo == "blake2s":
        digest = hashlib.blake2s(text_bytes).digest()
    else:
        raise ValueError(f"Unsupported algorithm: {algo}")

    # Encoding options
    if encoding is None or encoding == "hex":
        return digest.hex()
    elif encoding == "base64":
        return base64.b64encode(digest).decode()
    elif encoding == "urlsafe_b64":
        return base64.urlsafe_b64encode(digest).decode()
    elif encoding == "binary":
        return digest
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")

def hash_file(filepath, algo="sha256", encoding=None, chunk_size=65536):
    """
    Hashes a file using the selected algorithm.
    Optionally encodes the hash output.
    """
    algo = algo.lower()
    if algo not in hashlib.algorithms_available:
        raise ValueError(f"Unsupported algorithm: {algo}")

    h = hashlib.new(algo)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    digest = h.digest()

    # Encoding options
    if encoding is None or encoding == "hex":
        return digest.hex()
    elif encoding == "base64":
        return base64.b64encode(digest).decode()
    elif encoding == "urlsafe_b64":
        return base64.urlsafe_b64encode(digest).decode()
    elif encoding == "binary":
        return digest
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")

# === BCRYPT HASHING (used for password storage) ===

def bcrypt_hash(text, rounds=12):
    """
    Returns a bcrypt hash of the text.
    """
    salt = bcrypt.gensalt(rounds)
    hashed = bcrypt.hashpw(text.encode(), salt)
    return hashed.decode()

def bcrypt_verify(text, hashed):
    """
    Verifies a bcrypt hash.
    """
    return bcrypt.checkpw(text.encode(), hashed.encode())

# === "Dehashing" (Brute-force for simple hashes) ===

def brute_force_hash(target_hash, algo="sha256", wordlist=None, encoding=None):
    """
    Attempts to brute-force a hash using a wordlist.
    Returns the plaintext if found, else None.
    """
    if wordlist is None:
        raise ValueError("A wordlist must be provided for brute-force.")

    with open(wordlist, "r", errors="ignore") as f:
        for line in f:
            candidate = line.strip()
            if not candidate:
                continue
            candidate_hash = hash_text(candidate, algo=algo, encoding=encoding)
            if candidate_hash == target_hash:
                return candidate
    return None

# === Encoding/Decoding Utilities ===

def encode_text(text, encoding="base64"):
    """
    Encodes text using the specified encoding.
    Supported: base64, urlsafe_b64, hex, ascii85, base32
    """
    text_bytes = text.encode()
    encoding = encoding.lower()
    if encoding == "base64":
        return base64.b64encode(text_bytes).decode()
    elif encoding == "urlsafe_b64":
        return base64.urlsafe_b64encode(text_bytes).decode()
    elif encoding == "hex":
        return binascii.hexlify(text_bytes).decode()
    elif encoding == "ascii85":
        return base64.a85encode(text_bytes).decode()
    elif encoding == "base32":
        return base64.b32encode(text_bytes).decode()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")

def decode_text(encoded, encoding="base64"):
    """
    Decodes text using the specified encoding.
    Supported: base64, urlsafe_b64, hex, ascii85, base32
    """
    encoding = encoding.lower()
    if encoding == "base64":
        return base64.b64decode(encoded).decode()
    elif encoding == "urlsafe_b64":
        return base64.urlsafe_b64decode(encoded).decode()
    elif encoding == "hex":
        return binascii.unhexlify(encoded).decode()
    elif encoding == "ascii85":
        return base64.a85decode(encoded).decode()
    elif encoding == "base32":
        return base64.b32decode(encoded).decode()
    else:
        raise ValueError(f"Unsupported encoding: {encoding}")