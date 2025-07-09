from itertools import cycle
import string

def caesar_encrypt(text, shift):
    """
    Encrypts text using Caesar cipher with the given shift.
    """
    result = []
    shift = int(shift) % 26
    for char in text:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, shift):
    """
    Decrypts text using Caesar cipher with the given shift.
    """
    return caesar_encrypt(text, -int(shift))

def caesar_brute_force(ciphertext, dictionary=None, show_all=False):
    """
    Brute-forces Caesar cipher and prints all possible shifts.
    If a dictionary is provided, highlights likely English results.
    """
    print("[~] Brute-forcing Caesar cipher...")
    likely = []
    for shift in range(1, 26):
        guess = caesar_decrypt(ciphertext, shift)
        if dictionary:
            words = guess.split()
            matches = sum(1 for w in words if w.lower().strip(string.punctuation) in dictionary)
            if matches > 0:
                likely.append((shift, guess, matches))
        if show_all or not dictionary:
            print(f"[{shift:02}] {guess}")
    if dictionary and likely:
        print("\n[+] Likely English results:")
        for shift, guess, matches in sorted(likely, key=lambda x: -x[2]):
            print(f"[{shift:02}] {guess} (matches: {matches})")

def vigenere_encrypt(text, key):
    """
    Encrypts text using Vigenère cipher with the given key.
    """
    result = []
    key = [ord(k.lower()) - ord('a') for k in key if k.isalpha()]
    key_cycle = cycle(key)
    for char in text:
        if char.isupper():
            k = next(key_cycle)
            result.append(chr((ord(char) - ord('A') + k) % 26 + ord('A')))
        elif char.islower():
            k = next(key_cycle)
            result.append(chr((ord(char) - ord('a') + k) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(text, key):
    """
    Decrypts text using Vigenère cipher with the given key.
    """
    result = []
    key = [ord(k.lower()) - ord('a') for k in key if k.isalpha()]
    key_cycle = cycle(key)
    for char in text:
        if char.isupper():
            k = next(key_cycle)
            result.append(chr((ord(char) - ord('A') - k) % 26 + ord('A')))
        elif char.islower():
            k = next(key_cycle)
            result.append(chr((ord(char) - ord('a') - k) % 26 + ord('a')))
        else:
            result.append(char)
    return ''.join(result)

def xor_encrypt(text, key):
    """
    Encrypts text using XOR cipher with the given key.
    Returns bytes for binary safety.
    """
    return bytes([ord(c) ^ ord(k) for c, k in zip(text, cycle(key))])

def xor_decrypt(ciphertext, key):
    """
    Decrypts XOR-encrypted bytes using the given key.
    Returns the original string.
    """
    if isinstance(ciphertext, str):
        # If ciphertext is accidentally a string, treat as normal XOR
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(ciphertext, cycle(key)))
    return ''.join(chr(b ^ ord(k)) for b, k in zip(ciphertext, cycle(key)))

def is_printable(text):
    """
    Checks if all characters in text are printable.
    """
    return all(c in string.printable for c in text)