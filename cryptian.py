# filepath: c:\Users\RanVic\OneDrive\Desktop\CrypTian\cryptian.py
# cryptian.py - Main entry point for the Cryptian Tool

import os
import sys
from cli import main as cli_main
from rich import print
from rich.console import Console
from rich.panel import Panel

console = Console()

def main():
    # banner()
    cli_main()

if __name__ == "__main__":
    main()