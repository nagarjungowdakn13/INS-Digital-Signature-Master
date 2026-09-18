#!/usr/bin/env python3
"""
Digital Signature Tool

A complete digital signature tool using RSA and SHA-256 for signing
and verification of text messages and files.

Usage:
    python main.py                     # Interactive menu mode
    python main.py --generate-keys     # Generate new RSA keys
    python main.py --sign <file>       # Sign a file
    python main.py --verify <file>     # Verify a file signature
    python main.py --sign-text         # Sign text input (original mode)
    python main.py --help              # Show help
"""

import sys
import argparse
from typing import Optional, Tuple

# Ensure Unicode symbols (checkmarks, arrows) used in CLI output don't crash
# on Windows consoles that default to a non-UTF-8 codepage (e.g. cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8')
    except (AttributeError, ValueError):
        pass

from sha256 import SHA256
from rsa import RSA
from file_handler import FileHandler
from key_manager import KeyManager
from signature_manager import SignatureManager


class DigitalSignatureTool:
    """Main digital signature tool class."""

    def __init__(self, keys_dir: str = "keys"):
        """
        Initialize the Digital Signature Tool.
        
        Args:
            keys_dir: Directory for storing keys
        """
        self.sha256 = SHA256()
        self.key_manager = KeyManager(keys_dir=keys_dir)
        self.signature_manager = SignatureManager()
        self.rsa: Optional[RSA] = None
        self.key_size = 1024

    def generate_keys(self, key_size: int = 1024) -> Tuple[str, str]:
        """
        Generate new RSA key pair and save to files.
        
        Args:
            key_size: Key size in bits (1024, 2048, or 4096)
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        print(f"\nGenerating {key_size}-bit RSA key pair...")
        
        self.key_size = key_size
        self.rsa = RSA(key_length=key_size)
        
        # Save keys
        private_path, public_path = self.key_manager.save_keys(
            self.rsa.get_public_key(),
            self.rsa.get_private_key(),
            key_size=key_size
        )
        
        print("Keys generated successfully!")
        print(f"Private key saved to: {private_path}")
        print(f"Public key saved to: {public_path}")
        
        return private_path, public_path

    def load_keys(self) -> bool:
        """
        Load existing keys from files.
        
        Returns:
            True if keys loaded successfully, False otherwise
        """
        try:
            public_key, private_key = self.key_manager.load_keys()
            
            # Create RSA instance and set keys
            self.rsa = RSA(key_length=1024)  # Dummy initialization
            self.rsa.set_keys(public_key, private_key)
            
            # Get key info
            key_info = self.key_manager.get_key_info()
            if key_info:
                self.key_size = key_info.get("key_size", 1024)
            
            return True
        except FileNotFoundError:
            return False
        except ValueError as e:
            print(f"Error loading keys: {e}")
            return False

    def ensure_keys_available(self) -> bool:
        """
        Ensure RSA keys are available, loading from files if needed.
        
        Returns:
            True if keys are available, False otherwise
        """
        if self.rsa is not None:
            return True
        
        if self.key_manager.keys_exist():
            return self.load_keys()
        
        print("\nNo RSA keys found!")
        print("Please generate keys first using --generate-keys or option 1 in the menu.")
        return False

    def sign_file(self, filepath: str) -> Optional[str]:
        """
        Sign a file and create signature file.
        
        Args:
            filepath: Path to the file to sign
            
        Returns:
            Path to the signature file, or None if failed
        """
        if not self.ensure_keys_available():
            return None
        
        try:
            print(f"\nSigning file: {filepath}")
            
            # Read file
            print("Reading file... ", end="", flush=True)
            file_content = FileHandler.read_file_as_bytes(filepath)
            print("[OK]")
            
            # Calculate hash
            print("Calculating SHA-256 hash... ", end="", flush=True)
            file_hash = self.sha256.hash(file_content)
            hash_hex = file_hash.hex().upper()
            print("[OK]")
            print(f"  Hash: {hash_hex}")
            
            # Sign the hash
            print("Signing with private key... ", end="", flush=True)
            signature = self.rsa.sign(file_hash)
            print("[OK]")
            
            # Create signature file
            print("Creating signature file... ", end="", flush=True)
            sig_path = self.signature_manager.create_signature_file(
                original_filepath=filepath,
                signature=signature,
                key_size=self.key_size
            )
            print("[OK]")
            
            print(f"\nSignature saved to: {sig_path}")
            print("File signed successfully!")
            
            return sig_path
            
        except FileNotFoundError as e:
            print(f"\nError: {e}")
            return None
        except Exception as e:
            print(f"\nError signing file: {e}")
            return None

    def verify_file(self, filepath: str, signature_path: Optional[str] = None) -> bool:
        """
        Verify a file's digital signature.
        
        Args:
            filepath: Path to the file to verify
            signature_path: Path to signature file (auto-detected if not provided)
            
        Returns:
            True if signature is valid, False otherwise
        """
        if not self.ensure_keys_available():
            return False
        
        # Auto-detect signature path if not provided
        if signature_path is None:
            signature_path = filepath + ".sig"
        
        try:
            print(f"\nVerifying file: {filepath}")
            
            # Load signature
            print("Loading signature... ", end="", flush=True)
            sig_data = self.signature_manager.load_signature_file(signature_path)
            signature_bytes = sig_data["signature_bytes"]
            print("[OK]")
            
            # Read file
            print("Reading file... ", end="", flush=True)
            file_content = FileHandler.read_file_as_bytes(filepath)
            print("[OK]")
            
            # Calculate hash
            print("Calculating file hash... ", end="", flush=True)
            file_hash = self.sha256.hash(file_content)
            print("[OK]")
            
            # Verify signature
            print("Verifying signature... ", end="", flush=True)
            is_valid = self.rsa.verify_signature(signature_bytes, file_hash)
            print("[OK]")
            
            # Get signature info and display result
            sig_info = self.signature_manager.get_signature_info(signature_path)
            result = self.signature_manager.format_verification_result(
                is_valid, sig_info, filepath
            )
            print(result)
            
            return is_valid
            
        except FileNotFoundError as e:
            print(f"\nError: {e}")
            return False
        except ValueError as e:
            print(f"\nError: Invalid signature file - {e}")
            return False
        except Exception as e:
            print(f"\nError verifying file: {e}")
            return False

    def sign_text(self, message: Optional[str] = None) -> None:
        """
        Sign text input (original functionality).
        
        Args:
            message: Optional message to sign (prompts if not provided)
        """
        # Generate new keys for text signing (original behavior)
        print("\n=== Text Signing Mode ===")
        print("(Simulating Bob signing and Alice verifying)")
        print()
        
        # Create new RSA instance for this session (like original)
        rsa = RSA(key_length=1024)
        
        # Get message
        if message is None:
            message = input("Enter message to sign: ")
        
        # === SIGNING PROCESS (Bob) ===
        print("\n--- Signing Process (Bob) ---")
        
        # Step 1: Bob generates message
        print(f"1. Message: '{message}'")
        
        # Step 2: Bob calculates hash
        message_bytes = message.encode('utf-8')
        bob_hash = self.sha256.hash(message_bytes)
        bob_hash_str = bob_hash.hex().upper()
        print(f"2. Bob's hash (SHA-256): {bob_hash_str}")
        
        # Step 3: Bob signs with private key
        print(f"3. Encrypting hash with private key...")
        private_key = rsa.get_private_key()
        public_key = rsa.get_public_key()
        
        # Sign the hash string (like original Java code)
        encrypted = rsa.encrypt(bob_hash_str.encode('utf-8'), private_key)
        print(f"   Bob's encrypted hash (signature): {encrypted.hex().upper()[:80]}...")
        
        # Step 4: Bob sends message with signature
        print("4. Bob sends message with signature attached\n")
        
        # === VERIFICATION PROCESS (Alice) ===
        print("--- Verification Process (Alice) ---")
        
        # Step 1: Alice receives message
        received_message = message
        print(f"1. Alice receives message: '{received_message}'")
        
        # Step 2: Alice calculates hash
        alice_hash = self.sha256.hash(received_message.encode('utf-8'))
        alice_hash_str = alice_hash.hex().upper()
        print(f"2. Alice's calculated hash: {alice_hash_str}")
        
        # Step 3: Alice decrypts signature with public key
        print("3. Alice decrypts signature with Bob's public key...")
        decrypted = rsa.decrypt(encrypted, public_key)
        decrypted_str = decrypted.decode('utf-8')
        print(f"   Decrypted hash: {decrypted_str}")
        
        # Step 4: Alice compares hashes
        print("4. Comparing hashes...")
        if decrypted_str == alice_hash_str:
            print("\n✓ Verification successful!")
            print("  Alice's decryption matches her calculated hash.")
            print("  → The message is signed by Bob!")
        else:
            print("\n✗ Verification failed!")
            print("  Alice's decryption does NOT match her calculated hash.")
            print("  → The message is NOT signed by Bob!")


def interactive_menu(tool: DigitalSignatureTool) -> None:
    """
    Display interactive menu and handle user choices.
    
    Args:
        tool: DigitalSignatureTool instance
    """
    while True:
        print("\n" + "=" * 50)
        print("       DIGITAL SIGNATURE TOOL")
        print("=" * 50)
        print("1. Generate RSA Keys")
        print("2. Sign a File")
        print("3. Verify a File")
        print("4. Sign Text (Console Input)")
        print("5. Show Key Info")
        print("6. Exit")
        print("-" * 50)
        
        try:
            choice = input("Choose an option (1-6): ").strip()
        except EOFError:
            break
        
        if choice == "1":
            # Generate keys
            print("\nKey Size Options:")
            print("  1. 1024 bits (fast, less secure)")
            print("  2. 2048 bits (recommended)")
            print("  3. 4096 bits (slow, most secure)")
            
            size_choice = input("Select key size (1-3) [default: 1]: ").strip()
            key_sizes = {"1": 1024, "2": 2048, "3": 4096}
            key_size = key_sizes.get(size_choice, 1024)
            
            tool.generate_keys(key_size)
            
        elif choice == "2":
            # Sign file
            filepath = input("\nEnter file path to sign: ").strip()
            if filepath:
                tool.sign_file(filepath)
            else:
                print("No file path provided.")
                
        elif choice == "3":
            # Verify file
            filepath = input("\nEnter file path to verify: ").strip()
            if not filepath:
                print("No file path provided.")
                continue
            
            sig_path = input("Enter signature file path (press Enter for auto-detect): ").strip()
            if not sig_path:
                sig_path = None
            
            tool.verify_file(filepath, sig_path)
            
        elif choice == "4":
            # Sign text
            tool.sign_text()
            
        elif choice == "5":
            # Show key info
            if tool.key_manager.keys_exist():
                info = tool.key_manager.get_key_info()
                print("\n--- Key Information ---")
                print(f"Key Size: {info.get('key_size', 'Unknown')} bits")
                print(f"Private Key: {info.get('private_key_path', 'Unknown')}")
                print(f"Public Key: {info.get('public_key_path', 'Unknown')}")
            else:
                print("\nNo keys found. Generate keys first using option 1.")
                
        elif choice == "6":
            print("\nGoodbye!")
            break
        else:
            print("\nInvalid option. Please choose 1-6.")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Digital Signature Tool - RSA signing and verification",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                           # Interactive menu
  python main.py --generate-keys           # Generate 1024-bit keys
  python main.py --generate-keys 2048      # Generate 2048-bit keys
  python main.py --sign document.pdf       # Sign a file
  python main.py --verify document.pdf     # Verify using auto-detected .sig file
  python main.py --verify doc.pdf doc.sig  # Verify with specific signature file
  python main.py --sign-text               # Sign text from console input
        """
    )
    
    parser.add_argument(
        "--generate-keys", 
        nargs="?", 
        const=1024, 
        type=int,
        metavar="KEYSIZE",
        help="Generate RSA key pair (default: 1024 bits)"
    )
    parser.add_argument(
        "--sign", 
        metavar="FILE",
        help="Sign a file"
    )
    parser.add_argument(
        "--verify", 
        nargs="+",
        metavar=("FILE", "SIGNATURE"),
        help="Verify a file (optionally specify signature file)"
    )
    parser.add_argument(
        "--sign-text", 
        action="store_true",
        help="Sign text from console input (original mode)"
    )
    parser.add_argument(
        "--keys-dir",
        default="keys",
        help="Directory for key storage (default: keys)"
    )
    
    args = parser.parse_args()
    
    # Create tool instance
    tool = DigitalSignatureTool(keys_dir=args.keys_dir)
    
    # Handle command-line arguments
    if args.generate_keys:
        key_size = args.generate_keys
        if key_size not in [1024, 2048, 4096]:
            print(f"Warning: Unusual key size {key_size}. Recommended: 1024, 2048, or 4096")
        tool.generate_keys(key_size)
        
    elif args.sign:
        tool.sign_file(args.sign)
        
    elif args.verify:
        filepath = args.verify[0]
        sig_path = args.verify[1] if len(args.verify) > 1 else None
        tool.verify_file(filepath, sig_path)
        
    elif args.sign_text:
        tool.sign_text()
        
    else:
        # No arguments - show interactive menu
        interactive_menu(tool)


if __name__ == "__main__":
    main()
