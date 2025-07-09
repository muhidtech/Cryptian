
# Cryptian

Cryptian is an advanced cryptography command-line interface (CLI) tool designed for encryption, decryption, hashing, and classic cipher implementations. It supports various algorithms and provides functionalities for brute-forcing encrypted data and hashes.

## Features

- **Symmetric Encryption**: Encrypt and decrypt files using Fernet and AES algorithms.
- **Asymmetric Encryption**: Generate RSA keys and perform encryption, decryption, and digital signatures.
- **Hashing**: Generate hashes using MD5, SHA1, SHA256, and bcrypt.
- **Brute-Force**: Crack hashes and encrypted texts using brute-force techniques.
- **Classic Ciphers**: Implement classic ciphers such as Caesar, Vigenère, and XOR.

## Installation

To install the required dependencies, create a virtual environment and run:

```
pip install -r requirements.txt
```

## Usage

Run the tool using the command line:

```
python cryptian.py [command] [options]
```

### Commands

- **Encrypt**: Encrypt a file using symmetric algorithms.
  ```
  cryptian encrypt -f <file> -k <key> -a <algorithm>
  ```

- **Decrypt**: Decrypt an encrypted file.
  ```
  cryptian decrypt -f <file> -k <key> -a <algorithm>
  ```

- **Hash**: Generate a hash from text or a file.
  ```
  cryptian hash -t <text> -a <algorithm>
  ```

- **Brute-Force**: Attempt to crack hashes or encrypted data.
  ```
  cryptian brute -a <algorithm> --hash <hash> -w <wordlist>
  ```

- **Classic Ciphers**: Use classic ciphers for encryption or decryption.
  ```
  cryptian classic -t <text> -c <cipher> -k <key>
  ```

## Examples

- Encrypt a file using Fernet:
  ```
  cryptian encrypt -f secret.txt -k key.key -a fernet
  ```

- Hash a file using SHA256:
  ```
  cryptian hash -f notes.txt -a sha256
  ```

- Brute-force an MD5 hash:
  ```
  cryptian brute -a md5 --hash d41d8cd98f00b204e9800998ecf8427e -w rockyou.txt
  ```

- Decrypt a file using AES:
  ```
  cryptian decrypt -f encrypted_file.aes -k key.key -a aes --iv <iv>
  ```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
