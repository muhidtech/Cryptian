#!/bin/bash
set -e

echo "🛠️  Cleaning previous builds..."
rm -rf build dist cryptian.spec

echo "🛠️  Building Cryptian executable..."
pyinstaller --onefile --name cryptian cryptian.py

echo "🛠️  Copying to /usr/local/bin (requires sudo)..."
sudo cp dist/cryptian /usr/local/bin/

echo "✅ Cryptian CLI is now available as 'cryptian'!"
echo "ℹ️  Run 'cryptian --help' to see available commands."