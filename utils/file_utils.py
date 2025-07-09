import os

# === File Utilities ===

def read_file(filepath, mode='rb', create_if_missing=False):
    """
    Reads a file in binary or text mode.
    If create_if_missing is True, creates the file if it doesn't exist.
    Returns file content (empty if just created).
    """
    if not os.path.exists(filepath):
        if create_if_missing:
            with open(filepath, 'wb' if 'b' in mode else 'w') as f:
                pass
            return b'' if 'b' in mode else ''
        raise FileNotFoundError(f"[!] File not found: {filepath}")
    with open(filepath, mode) as f:
        return f.read()


def write_file(filepath, data, mode='wb'):
    """
    Writes data to a file in binary or text mode.
    """
    with open(filepath, mode) as f:
        f.write(data)
    print(f"[+] File saved: {filepath}")


def file_exists(filepath):
    """
    Checks if a file exists.
    """
    return os.path.isfile(filepath)


# === Key Management ===

def save_key(key, filename=None):
    """
    Saves a key (Fernet or AES key) to a file.
    If filename is None, generates a unique filename.
    """
    if filename is None:
        base = "secret"
        ext = ".key"
        i = 1
        filename = f"{base}{ext}"
        while os.path.exists(filename):
            filename = f"{base}_{i}{ext}"
            i += 1
    write_file(filename, key, mode='wb')
    return filename


def load_key(filename="secret.key", create_if_missing=False):
    """
    Loads a key from a file.
    If create_if_missing is True, creates the file if it doesn't exist.
    """
    return read_file(filename, mode='rb', create_if_missing=create_if_missing)


# === Wordlist Reader ===

def read_wordlist(path, create_if_missing=False):
    """
    Loads a wordlist file and returns a list of words.
    If create_if_missing is True, creates the file if it doesn't exist.
    """
    if not file_exists(path):
        if create_if_missing:
            with open(path, 'w') as f:
                pass
            return []
        raise FileNotFoundError(f"[!] Wordlist not found: {path}")

    with open(path, 'r', errors='ignore') as f:
        return [line.strip() for line in f.readlines() if line.strip()]