import argparse
import threading
import sys
import os
from rich.console import Console
from rich import print
from rich.console import Console
from rich.panel import Panel
from core import symmetric, hashing, asymmetric, brute_force, classic
from utils import file_utils
from core.symmetric import generate_fernet_key, generate_aes_key_iv

console = Console()

def encrypt_file(args):
    try:
        if not os.path.exists(args.file):
            console.print(f"[red]Input file '{args.file}' not found. Please create it first.[/red]")
            return

        if args.algo == "fernet":
            key_path = args.key
            if not file_utils.file_exists(key_path):
                console.print(f"[yellow]Key file '{key_path}' not found.[/yellow]")
                if console.input("[bold cyan]Generate a new Fernet key? (y/n): [/bold cyan]").lower().startswith("y"):
                    key = generate_fernet_key()
                    file_utils.save_key(key, key_path)
                    console.print(f"[green]New Fernet key generated and saved to {key_path}[/green]")
                else:
                    console.print("[red]Encryption aborted: No key provided.[/red]")
                    return
            key = file_utils.load_key(key_path)
            symmetric.fernet_encrypt_file(args.file, key)
            console.print("[green]File encrypted with Fernet.[/green]")

        elif args.algo == "aes":
            key_path = args.key
            iv = args.iv.encode() if args.iv else None
            if not file_utils.file_exists(key_path):
                console.print(f"[yellow]Key file '{key_path}' not found.[/yellow]")
                if console.input("[bold cyan]Generate a new AES key? (y/n): [/bold cyan]").lower().startswith("y"):
                    key, generated_iv = generate_aes_key_iv()
                    file_utils.save_key(key, key_path)
                    console.print(f"[green]New AES key generated and saved to {key_path}[/green]")
                    if not iv:
                        iv = generated_iv
                        console.print(f"[green]Generated IV: {iv.hex()}[/green]")
                else:
                    console.print("[red]Encryption aborted: No key provided.[/red]")
                    return
            key = file_utils.load_key(key_path)
            if not iv:
                console.print("[red]No IV provided for AES encryption.[/red]")
                return
            symmetric.aes_encrypt_file(args.file, key, iv)
            console.print("[green]File encrypted with AES.[/green]")

        else:
            console.print("[red]Unknown algorithm specified.[/red]")
            return

        if getattr(args, "remove_original", False):
            try:
                os.remove(args.file)
                console.print(f"[yellow]Original file '{args.file}' deleted.[/yellow]")
            except Exception as e:
                console.print(f"[red]Failed to delete original file: {e}[/red]")
    except Exception as e:
        console.print(f"[red]Encryption error: {e}[/red]")

def decrypt_file(args):
    try:
        if args.algo == "fernet":
            key_path = args.key
            if not file_utils.file_exists(key_path):
                console.print(f"[red]Key file '{key_path}' not found. Cannot decrypt.[/red]")
                return
            key = file_utils.load_key(key_path)
            symmetric.fernet_decrypt_file(args.file, key)
            console.print("[green]File decrypted with Fernet.[/green]")

        elif args.algo == "aes":
            key_path = args.key
            iv = args.iv.encode() if args.iv else None
            if not file_utils.file_exists(key_path):
                console.print(f"[red]Key file '{key_path}' not found. Cannot decrypt.[/red]")
                return
            key = file_utils.load_key(key_path)
            if not iv:
                console.print("[red]No IV provided for AES decryption.[/red]")
                return
            symmetric.aes_decrypt_file(args.file, key, iv)
            console.print("[green]File decrypted with AES.[/green]")

        else:
            console.print("[red]Unknown algorithm specified.[/red]")
    except Exception as e:
        console.print(f"[red]Decryption error: {e}[/red]")

def handle_hash(args):
    try:
        content = args.text
        if args.file:
            content = file_utils.read_file(args.file).decode()

        if args.bcrypt:
            hashed = hashing.bcrypt_hash(content)
            print("[cyan]bcrypt hash:[/cyan]", hashed)
        else:
            hashed = hashing.hash_text(content, args.algo)
            print(f"[{args.algo}] hash:", hashed)
    except Exception as e:
        print(f"[red]Hashing error: {e}[/red]")

def handle_brute(args):
    try:
        if args.algo in ["md5", "sha1", "sha256"]:
            brute_force.brute_hash(args.hash, args.wordlist, args.algo)
        elif args.algo == "bcrypt":
            brute_force.brute_bcrypt(args.hash, args.wordlist)
        elif args.algo == "caesar":
            brute_force.brute_caesar(args.text)
        elif args.algo == "fernet":
            brute_force.brute_fernet_encrypted(args.text.encode(), args.wordlist)
        elif args.algo == "aes":
            brute_force.brute_aes_encrypted(file_utils.read_file(args.file), args.wordlist, args.iv.encode())
        else:
            print("[red]Brute-force not supported for this algorithm.")
    except Exception as e:
        print(f"[red]Brute-force error: {e}[/red]")

def handle_classic(args):
    try:
        if args.cipher == "caesar":
            if args.brute:
                classic.caesar_brute_force(args.text)
            else:
                result = classic.caesar_encrypt(args.text, args.key) if args.encrypt else classic.caesar_decrypt(args.text, args.key)
                print("[green]Result:[/green]", result)
        elif args.cipher == "vigenere":
            result = classic.vigenere_encrypt(args.text, args.key) if args.encrypt else classic.vigenere_decrypt(args.text, args.key)
            print("[green]Result:[/green]", result)
        elif args.cipher == "xor":
            result = classic.xor_encrypt(args.text, args.key)
            print("[green]Result:[/green]", result)
        else:
            print("[red]Unsupported classic cipher.")
    except Exception as e:
        print(f"[red]Classic cipher error: {e}[/red]")

def build_parser():
    parser = argparse.ArgumentParser(
        prog="cryptian",
        description="""
─────────────────────────────────────────────────────────────────────────────
CrypTian - 🔐 Advanced Cryptography CLI Tool
─────────────────────────────────────────────────────────────────────────────

[ DESCRIPTION ]
  CrypTian is a powerful CLI for encryption, decryption, hashing, brute-forcing,
  and classic ciphers. Supports modern and legacy algorithms for files and text.

[ COMMANDS & ARGUMENTS ]

  encrypt (e)    Encrypt files using Fernet or AES symmetric ciphers
    -f, --file FILE         File to encrypt (required)
    -k, --key KEY           Key file or string (required)
    -a, --algo ALGO         Algorithm: fernet (default) or aes
    -r, --remove-original   Delete original file after encryption
        --iv IV             AES IV (required if algo is aes)

  decrypt (d)    Decrypt files encrypted with Fernet or AES
    -f, --file FILE         Encrypted file (required)
    -k, --key KEY           Key file or string (required)
    -a, --algo ALGO         Algorithm: fernet (default) or aes
        --iv IV             AES IV (required if algo is aes)

  hash (H)       Hash text or files using MD5, SHA1, SHA256, or bcrypt
    -t, --text TEXT         Text to hash
    -f, --file FILE         File whose contents to hash
    -a, --algo ALGO         Algorithm: md5, sha1, sha256 (default: sha256)
        --bcrypt            Use bcrypt instead

  brute (B)      Brute-force hashes or encrypted data (AES, Fernet, Caesar, etc)
    -a, --algo ALGO         Algorithm: md5, sha1, sha256, bcrypt, aes, caesar, fernet
        --hash HASH         Hash to brute-force
        --file FILE         Encrypted file (for AES)
        --text TEXT         Encrypted text (for Caesar/Fernet)
    -w, --wordlist FILE     Wordlist file path
        --iv IV             AES IV if needed

  classic (c)    Classic ciphers: Caesar, Vigenere, XOR
    -t, --text TEXT         Text to encrypt or decrypt (required)
    -c, --cipher CIPHER     Cipher: caesar, vigenere, xor (required)
    -k, --key KEY           Key for cipher
        --encrypt           Encrypt mode
        --brute             Brute-force (Caesar only)

  --shell        Launch the interactive Cryptian shell

[ OPTIONS ]
  -h, --help                Show this help message and exit

[ EXAMPLES ]
  cryptian encrypt -f secret.txt -k key.key -a fernet
  cryptian encrypt -f myfile.txt -k aes.key -a aes --iv 1234567890abcdef
  cryptian decrypt -f secret.txt.enc -k key.key -a fernet
  cryptian hash -f notes.txt -a sha256
  cryptian hash -t "hello world" --bcrypt
  cryptian brute -a md5 --hash d41d8cd98f00b204e9800998ecf8427e -w rockyou.txt
  cryptian brute -a caesar --text "Khoor" 
  cryptian classic -t "Khoor" -c caesar --brute
  cryptian --shell

─────────────────────────────────────────────────────────────────────────────
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--shell", action="store_true", help="Launch the interactive Cryptian shell")

    sub = parser.add_subparsers(
        dest="command",
        title="Available Commands",
        metavar="{encrypt,e,decrypt,d,hash,H,brute,B,classic,c}",
        help="Type 'cryptian <command> -h' for more details on each command."
    )

    # Encrypt
    e = sub.add_parser(
        "encrypt", aliases=["e"],
        help="Encrypt files using Fernet or AES",
        description="""
Encrypt a file using Fernet or AES symmetric encryption.

Arguments:
  -f, --file   File to encrypt
  -k, --key    Key file or string
  -a, --algo   Algorithm (fernet or aes)
  --iv         AES IV (required if algo is aes)
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    e.add_argument("-f", "--file", required=True, help="File to encrypt")
    e.add_argument("-k", "--key", required=True, help="Key file or string")
    e.add_argument("-a", "--algo", default="fernet", choices=["fernet", "aes"], help="Algorithm (fernet or aes)")
    e.add_argument("-r", "--remove-original", action="store_true", help="Delete the original file after encryption")
    e.add_argument("--iv", help="AES IV (required if algo is aes)")
    e.set_defaults(func=encrypt_file)

    # Decrypt
    d = sub.add_parser(
        "decrypt", aliases=["d"],
        help="Decrypt files using Fernet or AES",
        description="""
Decrypt a file using Fernet or AES symmetric encryption.

Arguments:
  -f, --file   Encrypted file
  -k, --key    Key file or string
  -a, --algo   Algorithm (fernet or aes)
  --iv         AES IV (required if algo is aes)
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    d.add_argument("-f", "--file", required=True, help="Encrypted file")
    d.add_argument("-k", "--key", required=True, help="Key file or string")
    d.add_argument("-a", "--algo", default="fernet", choices=["fernet", "aes"], help="Algorithm (fernet or aes)")
    d.add_argument("--iv", help="AES IV (required if algo is aes)")
    d.set_defaults(func=decrypt_file)

    # Hash
    h = sub.add_parser(
        "hash", aliases=["H"],
        help="Hash text or files using MD5, SHA1, SHA256, or bcrypt",
        description="""
Hash text or file using MD5, SHA1, SHA256, or bcrypt.

Arguments:
  -t, --text     Text to hash
  -f, --file     File whose contents to hash
  -a, --algo     Algorithm (md5, sha1, sha256)
  --bcrypt       Use bcrypt instead
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    input_group = h.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-t", "--text", help="Text to hash")
    input_group.add_argument("-f", "--file", help="File whose contents to hash")
    h.add_argument("-a", "--algo", default="sha256", choices=["md5", "sha1", "sha256"], help="Algorithm")
    h.add_argument("--bcrypt", action="store_true", help="Use bcrypt instead")
    h.set_defaults(func=handle_hash)

    # Brute
    b = sub.add_parser(
        "brute", aliases=["B"],
        help="Brute-force hashes or encrypted data",
        description="""
Brute-force hashes or encrypted data (AES, Fernet, Caesar, etc).

Arguments:
  -a, --algo     Algorithm (md5, sha1, sha256, bcrypt, aes, caesar, fernet)
  --hash         Hash to brute-force
  --file         Encrypted file (for AES)
  --text         Encrypted text (for Caesar/Fernet)
  -w, --wordlist Wordlist file path
  --iv           AES IV if needed
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    b.add_argument("-a", "--algo", required=True, choices=["md5", "sha1", "sha256", "bcrypt", "aes", "caesar", "fernet"], help="Algorithm")
    b.add_argument("--hash", help="Hash to brute-force")
    b.add_argument("--file", help="Encrypted file (for AES)")
    b.add_argument("--text", help="Encrypted text (for Caesar/Fernet)")
    b.add_argument("-w", "--wordlist", help="Wordlist file path")
    b.add_argument("--iv", help="AES IV if needed")
    b.set_defaults(func=handle_brute)

    # Classic
    c = sub.add_parser(
        "classic", aliases=["c"],
        help="Classic ciphers: Caesar, Vigenere, XOR",
        description="""
Classic ciphers: Caesar, Vigenere, XOR.

Arguments:
  -t, --text     Text to encrypt or decrypt
  -c, --cipher   Cipher (caesar, vigenere, xor)
  -k, --key      Key for cipher
  --encrypt      Encrypt mode
  --brute        Brute-force (Caesar only)
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    c.add_argument("-t", "--text", required=True, help="Text to encrypt or decrypt")
    c.add_argument("-c", "--cipher", required=True, choices=["caesar", "vigenere", "xor"], help="Cipher")
    c.add_argument("-k", "--key", help="Key for cipher")
    c.add_argument("--encrypt", action="store_true", help="Encrypt mode")
    c.add_argument("--brute", action="store_true", help="Brute-force (Caesar only)")
    c.set_defaults(func=handle_classic)

    return parser

def main():
    ascii_art = """
     ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ █████╗ ███╗   ██╗
    ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔══██╗████╗  ██║
    ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║███████║██╔██╗ ██║
    ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██╔══██║██║╚██╗██║
    ╚██████╗██║  ██║   ██║   ██║        ██║   ██║██║  ██║██║ ╚████║
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝

    [bold red]github.com/muhidtech/Cryptian   |   by MuhidTech   |   v1.0.0-beta[/bold red]

    ─────────────────────────────────────────────────────────────────────────────
    [bold magenta]CrypTian - 🔐 Advanced Cryptography CLI Tool[/bold magenta]
    ─────────────────────────────────────────────────────────────────────────────
    """

    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    args = parser.parse_args()

    if not getattr(args, "shell", False):
        console.print(Panel(ascii_art, title="[bold magenta]Cryptian CLI[/bold magenta]", style="bold green"))

    # Launch shell if --shell is used
    if getattr(args, "shell", False):
        try:
            from shell import CryptianShell
            CryptianShell().loop()
        except Exception as e:
            console.print(f"[red]Failed to launch shell: {e}[/red]")
        sys.exit(0)

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    console.print("[bold cyan]🔐 Running Cryptian CLI...[/bold cyan]")

    try:
        thread = threading.Thread(target=args.func, args=(args,))
        thread.start()
        thread.join()
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")

    console.print("[bold green]\n✅ Operation Completed.[/bold green]") 

if __name__ == "__main__":
    main()