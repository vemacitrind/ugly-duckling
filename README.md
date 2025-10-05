# <img src="duckling.png" alt="Diagram of Duckling" width="35"/>  Ugly Duckling — File & Directory Encryption (Python 3)

`duckling.py` is CLI-based encryption/decryption tool built on top of the
[cryptography.fernet](https://cryptography.io/en/latest/fernet/) module.  
It is designed for **personal or application-level** encryption — not for full-disk or system-wide use.

---

## Features

- Encrypt or decrypt individual files **or entire directories** safely.
- Uses **Fernet symmetric encryption (AES-128 + HMAC)** for authenticated encryption.
- Automatically skips hidden and non-regular files.
- Stores encryption keys ly (default: `~/.config/duckling/model.key`).
- Protects against misuse on critical system paths (e.g. `/`, `/usr`, `/etc`, `/dev`).
- Clean, intuitive command-line interface.
- Written in pure Python 3 — no external dependencies beyond `cryptography`.

---

## Requirements

- **Python** ≥ 3.8  
- **cryptography** library  
  Install via:
  ```bash
  pip install cryptography

## Usage

python duckling.py [TARGET OPTIONS] [MODE OPTIONS] [KEY OPTIONS]

```
Target Options
Option	Description
-c, --current-dir	Operate on the current working directory.
-f PATH, --file PATH	Operate on a specific file or directory.
Mode Options (mutually exclusive)
Option	Description
-e, --encrypt	Encrypt the target.
-d, --decrypt	Decrypt the target.
Key Options
Option	Description
-k PATH, --key-path PATH	Path to save (when encrypting) or read (when decrypting) the key file.
Default: ~/.config/duckling/model.key
-K KEYSTRING, --key KEYSTRING	Provide a Fernet key string directly on the command line.
General Options
Option	Description
-h, --help	Show help and usage information.
```
## Examples
1. Encrypt current directory
```python
python duckling.py -c -e
```
Generates a new Fernet key and encrypts all regular files in the current directory and its subfolders.
The key is stored in ~/.config/duckling/model.key.
2. Encrypt a single file and specify a custom key path
```python
python duckling.py -f ./notes.txt -e -k ~/.config/duckling/notes.key
```
3. Decrypt using an existing key file
```python
python duckling.py -f ./notes.txt -d -k ~/.config/duckling/notes.key
```
4. Decrypt using a key string directly (less )
  ```python
  python duckling.py -f ./notes.txt -d -K "gAAAAAB..."
  ```
## Key Management

    Keys are everything: if the key is lost, your encrypted files are unrecoverable.

    Key files are created with chmod 600 permissions.

    Store them in:

        ~/.config/duckling/ (for user-level use), or

        /etc/duckling/keys/ (for system services, owned by root or a dedicated user).

    Backup keys (e.g., offline or encrypted storage).

⚠️ Safety Notes

    Duckling refuses to operate on critical system directories such as /, /usr, /etc, /bin, /dev, /proc, etc.

    This is not a ransomware or destructive encryption tool — it is a safe local file protector.

    Always test on copies of files first.

    Never share your encryption key publicly.

## Example Key File

Keys are URL-safe base64 strings, 44 characters long:
```
gAAAAABlZxv8xNIR0UQX0Y9I7gHcs9BiypFpzDLp7b4u8Kn-9MP0pPpQZm--C-VQhG1A==
```
To reuse a key:
```
python duckling.py -f ./data/file.txt -d -K "gAAAAAB..."
```
