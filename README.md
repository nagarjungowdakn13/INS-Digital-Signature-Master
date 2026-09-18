# Signet

Signet is a digital signature tool that implements RSA and SHA-256 entirely from scratch in pure Python — no `cryptography` or `hashlib` libraries. Sign and verify files or text via a CLI or web UI, pick a 1024/2048/4096-bit key, and watch the full hash → sign → verify pipeline end to end.

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

![Signet web interface](docs/preview.png)

## ✨ Features

- 🔏 **RSA from scratch** — key generation, encryption/decryption, and signing, with no external crypto libraries
- 🔢 **SHA-256 from scratch** — a pure Python hash implementation you can read start to finish
- 🌐 **Web interface** — generate keys, sign files, and verify signatures from the browser
- 💻 **Command-line interface** — the same operations, scriptable from the terminal
- 📄 **Sign any file** — text, PDFs, images, binaries, whatever you throw at it
- ✅ **Tamper detection** — verification catches any change to the file, down to a single bit
- 💾 **Key persistence** — keys are generated once and reused across sessions
- 🔑 **1024 / 2048 / 4096-bit keys** — trade off speed against strength

## 📁 Project Structure

```
Signet/
├── app.py                # Flask web server & API
├── main.py                # CLI application
├── sha256.py               # SHA-256 hashing implementation
├── rsa.py                  # RSA key generation, encryption/decryption, signing
├── file_handler.py         # File I/O operations
├── key_manager.py          # Key persistence (save/load keys)
├── signature_manager.py    # Signature file (.sig) handling
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Web interface
├── static/
│   ├── css/
│   │   └── style.css       # Styling
│   └── js/
│       └── app.js          # Frontend logic
├── keys/                   # Stored keys (auto-created, gitignored)
└── README.md
```

## 📋 Requirements

- Python 3.6 or higher
- Flask 2.0+ (for the web interface)

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/signet.git
   cd signet
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 🌐 Web Interface (Recommended)

Start the Flask web server:

```bash
python app.py
```

Then open your browser and navigate to:
```
http://127.0.0.1:5000
```

### Web Interface Features:

1. **Key Management** — generate RSA key pairs at different sizes
2. **Sign Files** — upload and sign any file, download the `.sig` signature
3. **Verify Files** — upload a file and signature to check authenticity
4. **Sign Text** — an interactive walkthrough of the full signing process (Bob signs, Alice verifies)

---

## 💻 Command-Line Interface

### Interactive Menu Mode

Run without arguments for an interactive menu:

```bash
python main.py
```

```
==================================================
       DIGITAL SIGNATURE TOOL
==================================================
1. Generate RSA Keys
2. Sign a File
3. Verify a File
4. Sign Text (Console Input)
5. Show Key Info
6. Exit
--------------------------------------------------
Choose an option (1-6):
```

### Command-Line Flags

#### Generate Keys

```bash
# Generate 1024-bit keys (default)
python main.py --generate-keys

# Generate 2048-bit keys (recommended)
python main.py --generate-keys 2048

# Generate 4096-bit keys (most secure, slowest)
python main.py --generate-keys 4096
```

#### Sign a File

```bash
python main.py --sign document.pdf
```

Output:
```
Signing file: document.pdf
Reading file... [OK]
Calculating SHA-256 hash... [OK]
  Hash: 9F86D081884C7D659A2FEAA0C55AD015...
Signing with private key... [OK]
Creating signature file... [OK]

Signature saved to: document.pdf.sig
File signed successfully!
```

#### Verify a File

```bash
# Auto-detect signature file (.sig)
python main.py --verify document.pdf

# Specify signature file explicitly
python main.py --verify document.pdf document.pdf.sig
```

Output:
```
✓ Signature is VALID

File: document.pdf
Algorithm: RSA-SHA256
Key Size: 2048 bits
Signed On: 2025-12-02T10:30:45
Original Filename: document.pdf

The file has not been modified since it was signed.
```

#### Sign Text (Original Mode)

```bash
python main.py --sign-text
```

Replicates the original demo where Bob signs a message and Alice verifies it.

### Help

```bash
python main.py --help
```

## How It Works

### Signing Process (Bob)

1. **Message/File Input** — Bob enters a message or selects a file
2. **Hash Generation** — a SHA-256 hash is computed
3. **Signature Creation** — the hash is encrypted with Bob's private key
4. **Output** — the signature is saved to a `.sig` file

### Verification Process (Alice)

1. **Receive File** — Alice receives the file and signature
2. **Hash Calculation** — SHA-256 hash of the received file is computed
3. **Signature Decryption** — the signature is decrypted with Bob's public key
4. **Comparison** — if the decrypted hash matches the calculated hash, the signature is valid

## Signature File Format (.sig)

Signatures are stored in JSON format:

```json
{
  "format_version": "1.0",
  "algorithm": "RSA-SHA256",
  "key_size": 2048,
  "timestamp": "2025-12-02T10:30:45.123456",
  "original_filename": "document.pdf",
  "signature": "BASE64_ENCODED_SIGNATURE_DATA"
}
```

## Example Session

### Text Signing Example

```bash
$ python main.py --sign-text

=== Text Signing Mode ===
(Simulating Bob signing and Alice verifying)

Enter message to sign: test

--- Signing Process (Bob) ---
1. Message: 'test'
2. Bob's hash (SHA-256): 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
3. Encrypting hash with private key...
   Bob's encrypted hash (signature): 6D02F9384B4A7936ADD6EBE9914FD5E51CCC42A4...
4. Bob sends message with signature attached

--- Verification Process (Alice) ---
1. Alice receives message: 'test'
2. Alice's calculated hash: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
3. Alice decrypts signature with Bob's public key...
   Decrypted hash: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
4. Comparing hashes...

✓ Verification successful!
  Alice's decryption matches her calculated hash.
  → The message is signed by Bob!
```

### File Signing Example

```bash
$ python main.py --generate-keys 2048
Generating 2048-bit RSA key pair...
Keys generated successfully!
Private key saved to: keys/private.key
Public key saved to: keys/public.key

$ python main.py --sign myfile.txt
Signing file: myfile.txt
Reading file... [OK]
Calculating SHA-256 hash... [OK]
Signing with private key... [OK]
Creating signature file... [OK]
Signature saved to: myfile.txt.sig

$ python main.py --verify myfile.txt
✓ Signature is VALID
```

## Security Notes

This project is built to demonstrate how RSA and SHA-256 work, not to protect anything that matters:

- It's textbook RSA — there's no OAEP/PSS padding, so it should never be used to sign or encrypt real, sensitive data
- Private keys are stored as plaintext JSON with no passphrase protection
- 2048-bit keys are a reasonable default if you want to see how larger keys behave; 4096-bit is slower with little extra teaching value
- Prefer well-audited libraries (e.g. `cryptography`, GPG) for anything outside of learning and experimentation

## License

This project is open source, released under the MIT License — see [LICENSE](LICENSE) for the full text. Feel free to use it for learning, teaching, or building on top of.

## Credits

Based on the original Java implementation by henmja, converted to Python with an expanded CLI, a web interface, and a from-scratch RSA/SHA-256 core.
