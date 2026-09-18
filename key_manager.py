"""
Key Manager Module

This module handles RSA key persistence - saving and loading
public/private keys to/from files.
"""

import os
import json
import base64
from typing import Tuple, Optional

from file_handler import FileHandler


class KeyManager:
    """Manage RSA key storage and retrieval."""
    
    DEFAULT_KEYS_DIR = "keys"
    PRIVATE_KEY_FILE = "private.key"
    PUBLIC_KEY_FILE = "public.key"

    def __init__(self, keys_dir: Optional[str] = None):
        """
        Initialize KeyManager.
        
        Args:
            keys_dir: Directory to store keys (default: 'keys/')
        """
        self.keys_dir = keys_dir or self.DEFAULT_KEYS_DIR
        FileHandler.ensure_directory_exists(self.keys_dir)

    def _get_private_key_path(self) -> str:
        """Get full path to private key file."""
        return os.path.join(self.keys_dir, self.PRIVATE_KEY_FILE)

    def _get_public_key_path(self) -> str:
        """Get full path to public key file."""
        return os.path.join(self.keys_dir, self.PUBLIC_KEY_FILE)

    def save_keys(self, public_key: Tuple[int, int], private_key: Tuple[int, int], 
                  key_size: int = 1024) -> Tuple[str, str]:
        """
        Save RSA key pair to files.
        
        Keys are saved in a JSON format with Base64 encoded values for readability.
        
        Args:
            public_key: Tuple of (e, n) for public key
            private_key: Tuple of (d, n) for private key
            key_size: Key size in bits for metadata
            
        Returns:
            Tuple of (private_key_path, public_key_path)
        """
        # Save private key
        private_key_data = {
            "type": "RSA PRIVATE KEY",
            "key_size": key_size,
            "d": self._int_to_base64(private_key[0]),
            "n": self._int_to_base64(private_key[1])
        }
        
        private_key_path = self._get_private_key_path()
        FileHandler.write_text_to_file(
            private_key_path, 
            json.dumps(private_key_data, indent=2)
        )
        
        # Save public key
        public_key_data = {
            "type": "RSA PUBLIC KEY",
            "key_size": key_size,
            "e": self._int_to_base64(public_key[0]),
            "n": self._int_to_base64(public_key[1])
        }
        
        public_key_path = self._get_public_key_path()
        FileHandler.write_text_to_file(
            public_key_path, 
            json.dumps(public_key_data, indent=2)
        )
        
        return private_key_path, public_key_path

    def load_keys(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Load RSA key pair from files.
        
        Returns:
            Tuple of (public_key, private_key) where each is (exponent, modulus)
            
        Raises:
            FileNotFoundError: If key files don't exist
            ValueError: If key files are invalid
        """
        # Load private key
        private_key_path = self._get_private_key_path()
        if not FileHandler.file_exists(private_key_path):
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        
        try:
            private_key_json = FileHandler.read_text_from_file(private_key_path)
            private_key_data = json.loads(private_key_json)
            d = self._base64_to_int(private_key_data["d"])
            n_private = self._base64_to_int(private_key_data["n"])
            private_key = (d, n_private)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid private key file format: {e}")
        
        # Load public key
        public_key_path = self._get_public_key_path()
        if not FileHandler.file_exists(public_key_path):
            raise FileNotFoundError(f"Public key not found: {public_key_path}")
        
        try:
            public_key_json = FileHandler.read_text_from_file(public_key_path)
            public_key_data = json.loads(public_key_json)
            e = self._base64_to_int(public_key_data["e"])
            n_public = self._base64_to_int(public_key_data["n"])
            public_key = (e, n_public)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid public key file format: {e}")
        
        return public_key, private_key

    def load_public_key(self) -> Tuple[int, int]:
        """
        Load only the public key from file.
        
        Returns:
            Public key tuple (e, n)
        """
        public_key_path = self._get_public_key_path()
        if not FileHandler.file_exists(public_key_path):
            raise FileNotFoundError(f"Public key not found: {public_key_path}")
        
        try:
            public_key_json = FileHandler.read_text_from_file(public_key_path)
            public_key_data = json.loads(public_key_json)
            e = self._base64_to_int(public_key_data["e"])
            n = self._base64_to_int(public_key_data["n"])
            return (e, n)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid public key file format: {e}")

    def load_private_key(self) -> Tuple[int, int]:
        """
        Load only the private key from file.
        
        Returns:
            Private key tuple (d, n)
        """
        private_key_path = self._get_private_key_path()
        if not FileHandler.file_exists(private_key_path):
            raise FileNotFoundError(f"Private key not found: {private_key_path}")
        
        try:
            private_key_json = FileHandler.read_text_from_file(private_key_path)
            private_key_data = json.loads(private_key_json)
            d = self._base64_to_int(private_key_data["d"])
            n = self._base64_to_int(private_key_data["n"])
            return (d, n)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"Invalid private key file format: {e}")

    def keys_exist(self) -> bool:
        """
        Check if both key files exist.
        
        Returns:
            True if both keys exist, False otherwise
        """
        return (FileHandler.file_exists(self._get_private_key_path()) and 
                FileHandler.file_exists(self._get_public_key_path()))

    def get_key_info(self) -> Optional[dict]:
        """
        Get information about stored keys.
        
        Returns:
            Dictionary with key information or None if keys don't exist
        """
        if not self.keys_exist():
            return None
        
        try:
            public_key_json = FileHandler.read_text_from_file(self._get_public_key_path())
            public_key_data = json.loads(public_key_json)
            return {
                "key_size": public_key_data.get("key_size", "Unknown"),
                "public_key_path": self._get_public_key_path(),
                "private_key_path": self._get_private_key_path()
            }
        except Exception:
            return None

    @staticmethod
    def _int_to_base64(value: int) -> str:
        """Convert integer to base64 encoded string."""
        # Convert to bytes
        byte_length = (value.bit_length() + 7) // 8
        value_bytes = value.to_bytes(byte_length, byteorder='big')
        # Encode as base64
        return base64.b64encode(value_bytes).decode('utf-8')

    @staticmethod
    def _base64_to_int(encoded: str) -> int:
        """Convert base64 encoded string to integer."""
        value_bytes = base64.b64decode(encoded.encode('utf-8'))
        return int.from_bytes(value_bytes, byteorder='big')


if __name__ == "__main__":
    # Test KeyManager
    print("Testing KeyManager...")
    
    from rsa import RSA
    
    # Generate keys
    rsa = RSA(key_length=1024)
    print("Generated RSA keys")
    
    # Save keys
    km = KeyManager(keys_dir="test_keys")
    private_path, public_path = km.save_keys(
        rsa.get_public_key(), 
        rsa.get_private_key(),
        key_size=1024
    )
    print(f"Saved private key to: {private_path}")
    print(f"Saved public key to: {public_path}")
    
    # Load keys
    public_key, private_key = km.load_keys()
    print(f"\nLoaded keys successfully")
    print(f"Public key (e): {public_key[0]}")
    print(f"Keys match: {public_key == rsa.get_public_key() and private_key == rsa.get_private_key()}")
    
    # Get key info
    info = km.get_key_info()
    print(f"\nKey info: {info}")
    
    # Cleanup
    import shutil
    shutil.rmtree("test_keys")
    print("\nCleaned up test keys")
