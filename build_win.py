import os
import shutil
import subprocess
import sys

def main():
    print("🛠️  Cleaning previous builds...")
    for folder in ['build', 'dist']:
        if os.path.exists(folder):
            shutil.rmtree(folder)
    if os.path.exists('cryptian.spec'):
        os.remove('cryptian.spec')

    print("🛠️  Building Cryptian executable...")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--onefile", "--name", "cryptian", "cryptian.py"],
        check=True
    )

    exe_path = os.path.join("dist", "cryptian.exe")
    if os.path.exists(exe_path):
        print(f"✅ Build complete! You can now run it as:\n    {exe_path}\n")
        print("ℹ️  Add the 'dist' folder to your PATH to run 'cryptian' from anywhere.")
        print("ℹ️  Or copy 'cryptian.exe' to a folder already in your PATH (like C:\\Windows).")
        print("ℹ️  Run 'cryptian --help' to see available commands.")
    else:
        print("❌ Build failed: cryptian.exe not found in dist/.")

if __name__ == "__main__":
    main()