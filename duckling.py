#!/usr/bin/env python3
"""
duckling.py by https://github.com/vemacitrind

Safe encryption/decryption CLI using cryptography.Fernet.

Usage examples:
  Encrypt current dir and save key:
    python duckling.py -c -e -k ~/.config/myapp/model.key

  Encrypt a single file and print key:
    python duckling.py -f ./data/model.txt -e

  Decrypt a file using a key file:
    python duckling.py -f ./data/model.txt -d -k ~/.config/myapp/model.key

  Decrypt using a key string:
    python duckling.py -f ./data/model.txt -d -K "gAAAAA..." 
"""

import argparse
import os
import sys
from cryptography.fernet import Fernet, InvalidToken
import stat

DEFAULT_KEY_PATH = os.path.expanduser("~/.config/myapp/model.key")
FORBIDDEN_TOPDIRS = {"/", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/etc", "/proc", "/sys", "/dev", "/run"}

def is_forbidden_target(path):
    """Return True if path is a forbidden system directory (or is '/')."""
    path = os.path.abspath(path)

    if path in FORBIDDEN_TOPDIRS:
        return True
    if path == os.path.abspath(os.sep):
        return True
    return False

def save_key(key_bytes: bytes, key_path: str):
    """Save key bytes to key_path with secure permissions (600)."""
    key_dir = os.path.dirname(os.path.abspath(key_path))
    os.makedirs(key_dir, mode=0o700, exist_ok=True)
    with open(key_path, "wb") as f:
        f.write(key_bytes)
    os.chmod(key_path, 0o600)

def load_key_from_file(key_path: str) -> bytes:
    """Load a key file (returns bytes). Raises FileNotFoundError if missing."""
    with open(key_path, "rb") as f:
        return f.read().strip()

def normalize_key_from_string(key_string: str) -> bytes:
    """Convert a key string to bytes (strip whitespace)."""
    return key_string.strip().encode()

def should_skip_file(filepath: str) -> bool:
    """Skip special files: symlinks, sockets, device files, fifos."""
    try:
        st = os.lstat(filepath)
    except OSError:
        return True
    # Skip symlinks
    if stat.S_ISLNK(st.st_mode):
        return True
    # Skip directories (we process files only)
    if stat.S_ISDIR(st.st_mode):
        return True
    # Skip sockets, fifos, block/char devices
    if stat.S_ISSOCK(st.st_mode) or stat.S_ISFIFO(st.st_mode) or stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
        return True
    return False

def encrypt_file(path: str, fernet: Fernet):
    """Encrypt single file in-place (reads/writes binary)."""
    if should_skip_file(path):
        print(f"Skipping non-regular file: {path}")
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        encrypted = fernet.encrypt(data)
        with open(path, "wb") as f:
            f.write(encrypted)
        print(f"Encrypted: {path}")
    except Exception as exc:
        print(f"ERROR encrypting {path}: {exc}")

def decrypt_file(path: str, fernet: Fernet):
    """Decrypt single file in-place (reads/writes binary)."""
    if should_skip_file(path):
        print(f"Skipping non-regular file: {path}")
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        decrypted = fernet.decrypt(data)  # may raise InvalidToken
        with open(path, "wb") as f:
            f.write(decrypted)
        print(f"Decrypted: {path}")
    except InvalidToken:
        print(f"ERROR decrypting {path}: Invalid key or corrupted data.")
    except Exception as exc:
        print(f"ERROR decrypting {path}: {exc}")

def traverse_and_process(target: str, fernet: Fernet, mode: str):
    """
    If target is a file: process that file.
    If target is a directory: walk the directory tree and process regular files.
    mode: "encrypt" or "decrypt"
    """
    target = os.path.abspath(target)
    if os.path.isfile(target):
        if mode == "encrypt":
            encrypt_file(target, fernet)
        else:
            decrypt_file(target, fernet)
        return

    if not os.path.isdir(target):
        print(f"Target does not exist or is not a file/directory: {target}")
        return

    for dirpath, dirnames, filenames in os.walk(target):
        # Skip hidden directories by default (as in earlier code)
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]
        for fname in filenames:
            path = os.path.join(dirpath, fname)
            # skip if inside forbidden topdirs (defensive)
            if is_forbidden_target(path):
                print(f"Skipping forbidden path: {path}")
                continue
            if mode == "encrypt":
                encrypt_file(path, fernet)
            else:
                decrypt_file(path, fernet)

# ---- CLI ----
def parse_args():
    p = argparse.ArgumentParser(description="Safe encrypt/decrypt using Fernet (operates on file or directory).")
    group_target = p.add_mutually_exclusive_group(required=True)
    group_target.add_argument("-c", "--current-dir", action="store_true",
                              help="Operate on the current working directory (mutually exclusive with -f).")
    group_target.add_argument("-f", "--file", metavar="PATH",
                              help="Path to single file or directory to operate on (mutually exclusive with -c).")

    group_mode = p.add_mutually_exclusive_group(required=True)
    group_mode.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the target.")
    group_mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the target.")

    p.add_argument("-k", "--key-path", metavar="KEYFILE", default=DEFAULT_KEY_PATH,
                   help=f"Key file path to save (on encrypt) or read (on decrypt). Default: {DEFAULT_KEY_PATH}")
    p.add_argument("-K", "--key", metavar="KEYSTRING",
                   help="Provide Fernet key string directly (overrides --key-path for reading).")
    return p.parse_args()

def main():
    args = parse_args()

    if args.current_dir:
        target = os.getcwd()
    else:
        target = os.path.abspath(args.file)

    # Safety check
    if is_forbidden_target(target):
        print(f"ERROR: Refusing to operate on forbidden system path: {target}")
        sys.exit(2)

    mode = "encrypt" if args.encrypt else "decrypt"

    key_bytes = None
    if mode == "encrypt":
        # Generate key
        key_bytes = Fernet.generate_key()
        # If key-path provided, save key; otherwise print for user to save.
        if args.key_path:
            try:
                save_key(key_bytes, args.key_path)
                print(f"Key generated and saved to: {args.key_path} (permissions set to 600)")
            except Exception as exc:
                print(f"ERROR: Failed to save key to {args.key_path}: {exc}")
                print("Key (printout follows):")
                print(key_bytes.decode())
        else:
            # Should not happen because key_path has default, but keep behavior:
            print("Generated key (save this securely):")
            print(key_bytes.decode())
    else:  # decrypt
        # If user supplied key string via -K use that; otherwise try loading from key-path
        if args.key:
            try:
                key_bytes = normalize_key_from_string(args.key)
            except Exception as exc:
                print(f"ERROR: invalid key string: {exc}")
                sys.exit(3)
        else:
            # Read from args.key_path (default or provided)
            try:
                key_bytes = load_key_from_file(args.key_path)
            except FileNotFoundError:
                print(f"ERROR: Key file not found: {args.key_path}")
                sys.exit(4)
            except Exception as exc:
                print(f"ERROR reading key file {args.key_path}: {exc}")
                sys.exit(4)

    # Validate key
    try:
        fernet = Fernet(key_bytes)
    except Exception as exc:
        print(f"ERROR: Invalid Fernet key: {exc}")
        sys.exit(5)

    # Target (file | directory)
    try:
        traverse_and_process(target, fernet, mode)
    except Exception as exc:
        print(f"Unhandled error during processing: {exc}")
        sys.exit(6)

    print(f"\nOperation completed: {mode} on {target}")

if __name__ == "__main__":
    main()
