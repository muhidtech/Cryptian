import sys
import shlex
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.syntax import Syntax
from core import symmetric, hashing, asymmetric, brute_force, classic
from utils import file_utils

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import WordCompleter
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

console = Console()

SHELL_BANNER = """
[bold magenta]
 ██████╗██████╗ ██╗   ██╗██████╗ ████████╗██╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██║██╔══██╗████╗  ██║
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║███████║██╔██╗ ██║
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║██╔══██║██║╚██╗██║
╚██████╗██║  ██║   ██║   ██║        ██║   ██║██║  ██║██║ ╚████║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold magenta]
[bold green]Welcome to Cryptian Interactive Shell! Type 'help' for commands.[/bold green]
"""

SHELL_COMMANDS = [
    "help", "set", "unset", "show", "encrypt", "decrypt", "hash", "brute", "classic",
    "clear", "history", "exit", "quit", "save", "load", "vars", "reset", "cat", "ls", "pwd", "edit"
]

class CryptianShell:
    def __init__(self):
        self.vars = {}
        self.running = True
        self.prompt = "[bold cyan]cryptian >[/bold cyan] "
        self.history = []
        self.session = None
        self.history_file = os.path.expanduser("~/.cryptian_shell_history")
        if PROMPT_TOOLKIT_AVAILABLE:
            from prompt_toolkit.formatted_text import ANSI
            self.prompt = ANSI("\x1b[1;36mcryptian > \x1b[0m")
            self.session = PromptSession(
                history=FileHistory(self.history_file),
                completer=WordCompleter(SHELL_COMMANDS, ignore_case=True),
                complete_while_typing=True
            )

    def print_banner(self):
        console.print(Panel(SHELL_BANNER, title="[bold magenta]Cryptian Shell[/bold magenta]", style="bold green"))

    def print_operation_header(self, operation):
        console.rule(f"[bold magenta]{operation.upper()} OPERATION[/bold magenta]")
        table = Table(title=f"{operation.title()} Details", show_lines=True)
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="white")
        for k, v in self.vars.items():
            table.add_row(k, str(v))
        console.print(table)
        console.rule()

    def help(self, *_):
        table = Table(title="Cryptian Shell Commands", show_lines=True)
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")
        table.add_row("set <var> <value>", "Set a variable (e.g., set file secret.txt)")
        table.add_row("unset <var>", "Unset a variable")
        table.add_row("show/vars", "Show all set variables")
        table.add_row("save <file>", "Save current variables to a file")
        table.add_row("load <file>", "Load variables from a file")
        table.add_row("reset", "Reset all variables")
        table.add_row("encrypt", "Encrypt using current variables")
        table.add_row("decrypt", "Decrypt using current variables")
        table.add_row("hash", "Hash using current variables")
        table.add_row("brute", "Brute-force using current variables")
        table.add_row("classic", "Classic ciphers using current variables")
        table.add_row("clear", "Clear the screen")
        table.add_row("history", "Show command history")
        table.add_row("cat <file>", "Show contents of a file")
        table.add_row("ls [dir]", "List files in a directory")
        table.add_row("pwd", "Show current working directory")
        table.add_row("edit <file>", "Edit a file in your default editor")
        table.add_row("exit/quit", "Exit the shell")
        table.add_section()
        table.add_row("[bold]Supported Variables[/bold]", "[bold]Description[/bold]")
        table.add_row("file", "File to encrypt/decrypt/hash")
        table.add_row("key", "Key file or string")
        table.add_row("algo", "Algorithm (fernet, aes, md5, sha1, sha256, bcrypt, caesar, etc)")
        table.add_row("iv", "AES IV (for AES)")
        table.add_row("text", "Text to hash or cipher")
        table.add_row("hash", "Hash to brute-force")
        table.add_row("wordlist", "Wordlist file path (optional, uses built-in if not set)")
        table.add_row("cipher", "Classic cipher (caesar, vigenere, xor)")
        table.add_row("encrypt", "Set to true for encryption (classic)")
        table.add_row("brute", "Set to true for brute-force (classic caesar)")
        console.print(table)
        console.print("\n[bold yellow]Examples:[/bold yellow]")
        console.print("  set file secret.txt")
        console.print("  set key key.key")
        console.print("  set algo fernet")
        console.print("  encrypt")
        console.print("  set text 'Khoor'")
        console.print("  set cipher caesar")
        console.print("  set brute true")
        console.print("  classic")
        console.print("  save session1.vars")
        console.print("  load session1.vars")
        console.print("  cat secret.txt")
        console.print("  ls utils/wordlists")
        console.print("  pwd")
        console.print("  edit secret.txt")

    def show_vars(self, *_):
        if not self.vars:
            console.print("[yellow]No variables set.[/yellow]")
            return
        table = Table(title="Current Variables")
        table.add_column("Variable", style="cyan")
        table.add_column("Value", style="white")
        for k, v in self.vars.items():
            table.add_row(k, str(v))
        console.print(table)

    def set_var(self, args):
        if len(args) < 2:
            console.print("[red]Usage: set <var> <value>[/red]")
            return
        self.vars[args[0]] = " ".join(args[1:])
        console.print(f"[green]Set {args[0]} = {self.vars[args[0]]}[/green]")

    def unset_var(self, args):
        if not args:
            console.print("[red]Usage: unset <var>[/red]")
            return
        if args[0] in self.vars:
            del self.vars[args[0]]
            console.print(f"[yellow]Unset {args[0]}[/yellow]")
        else:
            console.print(f"[red]Variable '{args[0]}' not set.[/red]")

    def clear(self, *_):
        console.clear()
        self.print_banner()

    def show_history(self, *_):
        if not self.history:
            console.print("[yellow]No history yet.[/yellow]")
            return
        for i, cmd in enumerate(self.history, 1):
            console.print(f"{i}: {cmd}")

    def save(self, args):
        if not args:
            console.print("[red]Usage: save <file>[/red]")
            return
        try:
            with open(args[0], "w", encoding="utf-8") as f:
                for k, v in self.vars.items():
                    f.write(f"{k}={v}\n")
            console.print(f"[green]Variables saved to {args[0]}[/green]")
        except Exception as e:
            console.print(f"[red]Save error: {e}[/red]")

    def load(self, args):
        if not args:
            console.print("[red]Usage: load <file>[/red]")
            return
        try:
            with open(args[0], "r", encoding="utf-8") as f:
                for line in f:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        self.vars[k] = v
            console.print(f"[green]Variables loaded from {args[0]}[/green]")
        except Exception as e:
            console.print(f"[red]Load error: {e}[/red]")

    def reset(self, *_):
        self.vars.clear()
        console.print("[yellow]All variables reset.[/yellow]")

    def cat(self, args):
        if not args:
            console.print("[red]Usage: cat <file>[/red]")
            return
        try:
            if os.name == "nt":
                os.system(f"type {args[0]}")
            else:
                with open(args[0], "r", encoding="utf-8") as f:
                    content = f.read()
                syntax = Syntax(content, "text", theme="ansi_dark", line_numbers=True)
                console.print(syntax)
        except Exception as e:
            console.print(f"[red]cat error: {e}[/red]")

    def ls(self, args):
        path = args[0] if args else "."
        try:
            if os.name == "nt":
                os.system(f'dir "{path}"')
            else:
                files = os.listdir(path)
                for f in files:
                    console.print(f)
        except Exception as e:
            console.print(f"[red]ls error: {e}[/red]")

    def pwd(self, *_):
        console.print(os.getcwd())

    def edit(self, args):
        if not args:
            console.print("[red]Usage: edit <file>[/red]")
            return
        file = args[0]
        editor = os.environ.get("EDITOR", "notepad" if os.name == "nt" else "nano")
        try:
            os.system(f"{editor} {file}")
        except Exception as e:
            console.print(f"[red]Edit error: {e}[/red]")

    def parse_vars(self, required):
        missing = [var for var in required if var not in self.vars]
        if missing:
            console.print(f"[red]Missing required variables: {', '.join(missing)}[/red]")
            return None
        return {k: self.vars[k] for k in required}

    def encrypt(self, *_):
        self.print_operation_header("Encrypt")
        required = ["file", "key", "algo"]
        args = self.parse_vars(required)
        if not args:
            return
        iv = self.vars.get("iv")
        try:
            if args["algo"] == "fernet":
                if not file_utils.file_exists(args["key"]):
                    console.print(f"[yellow]Key file '{args['key']}' not found.[/yellow]")
                    if console.input("[bold cyan]Generate a new Fernet key? (y/n): [/bold cyan]").lower().startswith("y"):
                        key = symmetric.generate_fernet_key()
                        file_utils.save_key(key, args["key"])
                        console.print(f"[green]New Fernet key generated and saved to {args['key']}[/green]")
                    else:
                        console.print("[red]Encryption aborted: No key provided.[/red]")
                        return
                key = file_utils.load_key(args["key"])
                symmetric.fernet_encrypt_file(args["file"], key)
                console.print("[green]File encrypted with Fernet.[/green]")
            elif args["algo"] == "aes":
                key_path = args["key"]
                iv_bytes = iv.encode() if isinstance(iv, str) else iv
                if not file_utils.file_exists(key_path):
                    console.print(f"[yellow]Key file '{key_path}' not found.[/yellow]")
                    if console.input("[bold cyan]Generate a new AES key? (y/n): [/bold cyan]").lower().startswith("y"):
                        key, generated_iv = symmetric.generate_aes_key_iv()
                        file_utils.save_key(key, key_path)
                        console.print(f"[green]New AES key generated and saved to {key_path}[/green]")
                        if not iv:
                            iv_bytes = generated_iv
                            console.print(f"[green]Generated IV: {iv_bytes.hex()}[/green]")
                    else:
                        console.print("[red]Encryption aborted: No key provided.[/red]")
                        return
                # Always load the key from the file!
                key = file_utils.load_key(key_path)
                if isinstance(key, str):
                    key = key.encode()
                if len(key) not in (16, 24, 32):
                    console.print(f"[red]AES key must be 16, 24, or 32 bytes, but got {len(key)} bytes.[/red]")
                    return
                symmetric.aes_encrypt_file(args["file"], key, iv_bytes)
                console.print("[green]File encrypted with AES.[/green]")
            else:
                console.print("[red]Unknown algorithm.[/red]")
        except Exception as e:
            console.print(f"[red]Encryption error: {e}[/red]")

    def decrypt(self, *_):
        self.print_operation_header("Decrypt")
        required = ["file", "key", "algo"]
        args = self.parse_vars(required)
        if not args:
            return
        iv = self.vars.get("iv")
        try:
            if args["algo"] == "fernet":
                if not file_utils.file_exists(args["key"]):
                    console.print(f"[red]Key file '{args['key']}' not found. Cannot decrypt.[/red]")
                    return
                key = file_utils.load_key(args["key"])
                symmetric.fernet_decrypt_file(args["file"], key)
                console.print("[green]File decrypted with Fernet.[/green]")
            elif args["algo"] == "aes":
                key_path = args["key"]
                iv_bytes = iv.encode() if isinstance(iv, str) else iv
                if not file_utils.file_exists(key_path):
                    console.print(f"[red]Key file '{key_path}' not found. Cannot decrypt.[/red]")
                    return
                # Always load the key from the file!
                key = file_utils.load_key(key_path)
                if isinstance(key, str):
                    key = key.encode()
                if len(key) not in (16, 24, 32):
                    console.print(f"[red]AES key must be 16, 24, or 32 bytes, but got {len(key)} bytes.[/red]")
                    return
                symmetric.aes_decrypt_file(args["file"], key, iv_bytes)
                console.print("[green]File decrypted with AES.[/green]")
            else:
                console.print("[red]Unknown algorithm.[/red]")
        except Exception as e:
            console.print(f"[red]Decryption error: {e}[/red]")

    def hash(self, *_):
        self.print_operation_header("Hash")
        try:
            if "text" in self.vars:
                content = self.vars["text"]
            elif "file" in self.vars:
                content = file_utils.read_file(self.vars["file"]).decode()
            else:
                console.print("[red]Set 'text' or 'file' variable.[/red]")
                return
            algo = self.vars.get("algo", "sha256")
            if self.vars.get("bcrypt"):
                hashed = hashing.bcrypt_hash(content)
                console.print(f"[cyan]bcrypt hash:[/cyan] {hashed}")
            else:
                hashed = hashing.hash_text(content, algo)
                console.print(f"[cyan]{algo} hash:[/cyan] {hashed}")
        except Exception as e:
            console.print(f"[red]Hashing error: {e}[/red]")

    def brute(self, *_):
        self.print_operation_header("Brute-force")
        try:
            algo = self.vars.get("algo")
            if not algo:
                console.print("[red]Set 'algo' variable.[/red]")
                return
            wordlist = self.vars.get("wordlist")
            iv = self.vars.get("iv")
            if algo in ["md5", "sha1", "sha256"]:
                brute_force.brute_hash(self.vars.get("hash"), wordlist, algo)
            elif algo == "bcrypt":
                brute_force.brute_bcrypt(self.vars.get("hash"), wordlist)
            elif algo == "caesar":
                brute_force.brute_caesar(self.vars.get("text"))
            elif algo == "fernet":
                brute_force.brute_fernet_encrypted(self.vars.get("text").encode(), wordlist)
            elif algo == "aes":
                brute_force.brute_aes_encrypted(file_utils.read_file(self.vars.get("file")), wordlist, iv.encode() if iv else None)
            else:
                console.print("[red]Brute-force not supported for this algorithm.[/red]")
        except Exception as e:
            console.print(f"[red]Brute-force error: {e}[/red]")

    def classic(self, *_):
        self.print_operation_header("Classic Cipher")
        try:
            cipher = self.vars.get("cipher")
            if not cipher:
                console.print("[red]Set 'cipher' variable.[/red]")
                return
            text = self.vars.get("text")
            key = self.vars.get("key")
            encrypt_mode = self.vars.get("encrypt", "false").lower() == "true"
            if cipher == "caesar":
                if self.vars.get("brute", "false").lower() == "true":
                    classic.caesar_brute_force(text)
                else:
                    result = classic.caesar_encrypt(text, key) if encrypt_mode else classic.caesar_decrypt(text, key)
                    console.print("[green]Result:[/green]", result)
            elif cipher == "vigenere":
                result = classic.vigenere_encrypt(text, key) if encrypt_mode else classic.vigenere_decrypt(text, key)
                console.print("[green]Result:[/green]", result)
            elif cipher == "xor":
                result = classic.xor_encrypt(text, key)
                console.print("[green]Result:[/green]", result)
            else:
                console.print("[red]Unsupported classic cipher.[/red]")
        except Exception as e:
            console.print(f"[red]Classic cipher error: {e}[/red]")

    def run_command(self, cmd, args):
        commands = {
            "help": self.help,
            "set": self.set_var,
            "unset": self.unset_var,
            "show": self.show_vars,
            "vars": self.show_vars,
            "save": self.save,
            "load": self.load,
            "reset": self.reset,
            "encrypt": self.encrypt,
            "decrypt": self.decrypt,
            "hash": self.hash,
            "brute": self.brute,
            "classic": self.classic,
            "clear": self.clear,
            "history": self.show_history,
            "cat": self.cat,
            "ls": self.ls,
            "pwd": self.pwd,
            "edit": self.edit,
            "exit": self.exit_shell,
            "quit": self.exit_shell,
        }
        func = commands.get(cmd)
        if func:
            func(args)
        else:
            console.print(f"[red]Unknown command: {cmd}[/red]")

    def exit_shell(self, *_):
        self.running = False
        console.print("[bold magenta]Goodbye![/bold magenta]")

    def loop(self):
        self.print_banner()
        while self.running:
            try:
                if PROMPT_TOOLKIT_AVAILABLE:
                    line = self.session.prompt(self.prompt, auto_suggest=None)
                else:
                    line = console.input(self.prompt)
                if not line.strip():
                    continue
                self.history.append(line)
                parts = shlex.split(line)
                cmd, *args = parts
                self.run_command(cmd, args)
            except (KeyboardInterrupt, EOFError):
                self.exit_shell()
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    CryptianShell().loop()