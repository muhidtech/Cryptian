from core import hashing, classic
from core.symmetric import fernet_decrypt_text, aes_decrypt_text, fernet_decrypt_file, aes_decrypt_file
from core.asymmetric import rsa_decrypt_text, rsa_decrypt_file
from utils.file_utils import read_wordlist, read_file, file_exists
import os
import base64
import binascii
from rich.console import Console


console = Console()


# === Built-in wordlist logic ===

def get_default_wordlist(algo):
    """
    Returns the path to a built-in wordlist for the given algorithm if available.
    """
    wordlists_dir = os.path.join(os.path.dirname(__file__), "..", "utils", "wordlists")
    mapping = {
        "caesar": "caesar.txt",
        "vigenere": "vigenere.txt",
        "xor": "xor.txt",
        "aes": "aes.txt",
        "fernet": "fernet.txt",
        "rsa": "rsa.txt",
        "bcrypt": "passwords.txt",
        "md5": "passwords.txt",
        "sha1": "passwords.txt",
        "sha256": "passwords.txt",
        "sha512": "passwords.txt",
        "blake2b": "passwords.txt",
        "blake2s": "passwords.txt",
    }
    fname = mapping.get(algo)
    if fname:
        path = os.path.abspath(os.path.join(wordlists_dir, fname))
        if os.path.exists(path):
            return path
    return None

def safe_read_wordlist(wordlist_path, algo):
    """
    Tries to read the given wordlist, falls back to built-in if not found.
    """
    try:
        if wordlist_path and os.path.exists(wordlist_path):
            return read_wordlist(wordlist_path)
        default = get_default_wordlist(algo)
        if default:
            console.print(f"[yellow]Using built-in wordlist for {algo}: {default}[/yellow]")
            return read_wordlist(default)
        raise FileNotFoundError(f"No wordlist found for {algo}.")
    except Exception as e:
        console.print(f"[red]Wordlist error: {e}[/red]")
        return []

def brute_hash(hash_value, wordlist_path, algo="md5", encoding=None):
    words = safe_read_wordlist(wordlist_path, algo)
    if not words:
        console.print("[red]No words loaded for brute-force.[/red]")
        return None
    console.print(f"[~] Loaded {len(words)} words for {algo} brute-force.")
    for word in words:
        try:
            guess_hash = hashing.hash_text(word, algo, encoding)
            if guess_hash == hash_value:
                console.print(f"[green][+] Hash cracked! → {word}[/green]")
                return word
        except Exception as e:
            console.print(f"[red]Hashing error: {e}[/red]")
    console.print("[red][-] Failed to crack hash.[/red]")
    return None

def brute_bcrypt(hash_value, wordlist_path):
    words = safe_read_wordlist(wordlist_path, "bcrypt")
    if not words:
        console.print("[red]No words loaded for bcrypt brute-force.[/red]")
        return None
    for word in words:
        try:
            if hashing.bcrypt_verify(word, hash_value):
                console.print(f"[green][+] Bcrypt cracked! → {word}[/green]")
                return word
        except Exception as e:
            console.print(f"[red]Bcrypt error: {e}[/red]")
    console.print("[red][-] Failed to crack bcrypt.[/red]")
    return None

def brute_caesar(ciphertext, dictionary=None, show_all=False):
    try:
        console.print("[~] Attempting Caesar brute-force...")
        if not dictionary:
            # Try built-in dictionary
            dict_path = get_default_wordlist("caesar")
            if dict_path:
                dictionary = set(read_wordlist(dict_path))
        classic.caesar_brute_force(ciphertext, dictionary=dictionary, show_all=show_all)
    except Exception as e:
        console.print(f"[red]Caesar brute-force error: {e}[/red]")

def brute_vigenere(ciphertext, wordlist_path):
    words = safe_read_wordlist(wordlist_path, "vigenere")
    if not words:
        console.print("[red]No keys loaded for Vigenère brute-force.[/red]")
        return None
    console.print(f"[~] Loaded {len(words)} keys for Vigenère brute-force.")
    for key in words:
        try:
            decrypted = classic.vigenere_decrypt(ciphertext, key)
            if classic.is_console.printable(decrypted):
                console.print(f"[green][+] Vigenère key found! → {key}[/green]")
                console.print("Decrypted:", decrypted)
                return key
        except Exception as e:
            console.print(f"[red]Vigenère error: {e}[/red]")
    console.print("[red][-] Failed to brute-force Vigenère.[/red]")
    return None

def brute_xor(ciphertext, wordlist_path):
    words = safe_read_wordlist(wordlist_path, "xor")
    if not words:
        console.print("[red]No keys loaded for XOR brute-force.[/red]")
        return None
    console.print(f"[~] Loaded {len(words)} keys for XOR brute-force.")
    for key in words:
        try:
            decrypted = classic.xor_decrypt(ciphertext, key)
            if classic.is_console.printable(decrypted):
                console.print(f"[green][+] XOR key found! → {key}[/green]")
                console.print("Decrypted:", decrypted)
                return key
        except Exception as e:
            console.print(f"[red]XOR error: {e}[/red]")
    console.print("[red][-] Failed to brute-force XOR.[/red]")
    return None

def brute_fernet_encrypted(ciphertext, wordlist_path, is_file=False, outpath=None):
    words = safe_read_wordlist(wordlist_path, "fernet")
    if not words:
        console.print("[red]No keys loaded for Fernet brute-force.[/red]")
        return None
    for key in words:
        try:
            key_bytes = key.encode()
            if is_file:
                fernet_decrypt_file(ciphertext, key_bytes, outpath=outpath, overwrite=True)
                console.print(f"[green][+] Fernet key found! → {key}[/green]")
                console.print(f"Decrypted file saved as: {outpath or (ciphertext+'.decrypted')}")
                return key
            else:
                decrypted = fernet_decrypt_text(ciphertext, key_bytes)
                console.print(f"[green][+] Fernet key found! → {key}[/green]")
                console.print("Decrypted:", decrypted)
                return key
        except Exception as e:
            console.print(f"[yellow]Fernet key '{key}' failed: {e}[/yellow]")
    console.print("[red][-] Failed to brute-force Fernet encryption.[/red]")
    return None

def brute_aes_encrypted(ciphertext, wordlist_path, iv, is_file=False, outpath=None):
    words = safe_read_wordlist(wordlist_path, "aes")
    if not words:
        console.print("[red]No keys loaded for AES brute-force.[/red]")
        return None
    for word in words:
        try:
            key = word.encode()
            if len(key) not in [16, 24, 32]:
                continue
            if is_file:
                aes_decrypt_file(ciphertext, key, iv, outpath=outpath, overwrite=True)
                console.print(f"[green][+] AES key found! → {word}[/green]")
                console.print(f"Decrypted file saved as: {outpath or (ciphertext+'.decrypted')}")
                return word
            else:
                plaintext = aes_decrypt_text(ciphertext, key, iv)
                if classic.is_console.printable(plaintext):
                    console.print(f"[green][+] AES key found! → {word}[/green]")
                    console.print("Decrypted:", plaintext)
                    return word
        except Exception as e:
            console.print(f"[yellow]AES key '{word}' failed: {e}[/yellow]")
    console.print("[red][-] Failed to brute-force AES.[/red]")
    return None

def brute_rsa_encrypted(ciphertext, wordlist_path, is_file=False, outpath=None):
    words = safe_read_wordlist(wordlist_path, "rsa")
    if not words:
        console.print("[red]No keys loaded for RSA brute-force.[/red]")
        return None
    for priv_key_file in words:
        try:
            if is_file:
                rsa_decrypt_file(ciphertext, private_key_file=priv_key_file, outpath=outpath, overwrite=True)
                console.print(f"[green][+] RSA private key found! → {priv_key_file}[/green]")
                console.print(f"Decrypted file saved as: {outpath or (ciphertext+'.decrypted')}")
                return priv_key_file
            else:
                decrypted = rsa_decrypt_text(ciphertext, private_key_file=priv_key_file)
                console.print(f"[green][+] RSA private key found! → {priv_key_file}[/green]")
                console.print("Decrypted:", decrypted)
                return priv_key_file
        except Exception as e:
            console.print(f"[yellow]RSA key '{priv_key_file}' failed: {e}[/yellow]")
    console.print("[red][-] Failed to brute-force RSA private key.[/red]")
    return None

def brute_file(filepath, algo, wordlist_path=None, iv=None, outpath=None):
    """
    Brute-forces encrypted files for supported algorithms.
    """
    if not file_exists(filepath):
        console.print(f"[red][!] File not found: {filepath}[/red]")
        return None

    if algo == "fernet":
        return brute_fernet_encrypted(filepath, wordlist_path, is_file=True, outpath=outpath)
    elif algo == "aes":
        if iv is None:
            console.print("[red][!] IV required for AES file brute-force.[/red]")
            return None
        return brute_aes_encrypted(filepath, wordlist_path, iv, is_file=True, outpath=outpath)
    elif algo == "rsa":
        return brute_rsa_encrypted(filepath, wordlist_path, is_file=True, outpath=outpath)
    elif algo == "xor":
        data = read_file(filepath, mode='rb')
        return brute_xor(data, wordlist_path)
    else:
        console.print(f"[red][!] Brute-forcing for '{algo}' files is not supported.[/red]")
        return None

def brute_text(ciphertext, algo, wordlist_path=None, iv=None):
    """
    Brute-forces encrypted text for supported algorithms.
    """
    if algo == "fernet":
        return brute_fernet_encrypted(ciphertext, wordlist_path)
    elif algo == "aes":
        if iv is None:
            console.print("[red][!] IV required for AES text brute-force.[/red]")
            return None
        try:
            try:
                ct_bytes = base64.b64decode(ciphertext)
            except Exception:
                ct_bytes = binascii.unhexlify(ciphertext)
        except Exception:
            ct_bytes = ciphertext.encode()
        return brute_aes_encrypted(ct_bytes, wordlist_path, iv)
    elif algo == "rsa":
        return brute_rsa_encrypted(ciphertext, wordlist_path)
    elif algo == "caesar":
        return brute_caesar(ciphertext)
    elif algo == "vigenere":
        return brute_vigenere(ciphertext, wordlist_path)
    elif algo == "xor":
        try:
            try:
                ct_bytes = base64.b64decode(ciphertext)
            except Exception:
                ct_bytes = binascii.unhexlify(ciphertext)
        except Exception:
            ct_bytes = ciphertext.encode()
        return brute_xor(ct_bytes, wordlist_path)
    else:
        console.print(f"[red][!] Brute-forcing for '{algo}' text is not supported.[/red]")
        return None

def brute_any(target, algo, wordlist_path=None, iv=None, is_file=False, outpath=None, encoding=None, dictionary=None):
    """
    Universal brute-force dispatcher for all supported cryptography types.
    """
    if algo in ["md5", "sha1", "sha256", "sha512", "blake2b", "blake2s"]:
        return brute_hash(target, wordlist_path, algo=algo, encoding=encoding)
    elif algo == "bcrypt":
        return brute_bcrypt(target, wordlist_path)
    elif algo == "fernet":
        if is_file:
            return brute_fernet_encrypted(target, wordlist_path, is_file=True, outpath=outpath)
        else:
            return brute_fernet_encrypted(target, wordlist_path)
    elif algo == "aes":
        if is_file:
            return brute_aes_encrypted(target, wordlist_path, iv, is_file=True, outpath=outpath)
        else:
            return brute_aes_encrypted(target, wordlist_path, iv)
    elif algo == "rsa":
        if is_file:
            return brute_rsa_encrypted(target, wordlist_path, is_file=True, outpath=outpath)
        else:
            return brute_rsa_encrypted(target, wordlist_path)
    elif algo == "caesar":
        return brute_caesar(target, dictionary=dictionary)
    elif algo == "vigenere":
        return brute_vigenere(target, wordlist_path)
    elif algo == "xor":
        if is_file:
            data = read_file(target, mode='rb')
            return brute_xor(data, wordlist_path)
        else:
            try:
                try:
                    ct_bytes = base64.b64decode(target)
                except Exception:
                    ct_bytes = binascii.unhexlify(target)
            except Exception:
                ct_bytes = target.encode()
            return brute_xor(ct_bytes, wordlist_path)
    else:
        console.print(f"[red][!] Brute-forcing for '{algo}' is not supported.[/red]")
        return None