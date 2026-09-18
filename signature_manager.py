"""
Signature Manager Module

This module handles digital signature file format, creation, and verification.
"""

import os
import json
import base64
from datetime import datetime
from typing import Optional, Dict, Any

from file_handler import FileHandler


class SignatureManager:
    """Manage digital signature file operations."""
    
    SIGNATURE_EXTENSION = ".sig"
    ALGORITHM = "RSA-SHA256"

    def __init__(self):
        """Initialize SignatureManager."""
        pass

    def create_signature_file(
        self,
        original_filepath: str,
        signature: bytes,
        key_size: int = 1024,
        output_path: Optional[str] = None
    ) -> str:
        """
        Create a signature file (.sig) with metadata.
        
        Args:
            original_filepath: Path to the original file that was signed
            signature: The digital signature bytes
            key_size: RSA key size used for signing
            output_path: Optional custom output path for signature file
            
        Returns:
            Path to the created signature file
        """
        # Generate signature file path
        if output_path is None:
            output_path = original_filepath + self.SIGNATURE_EXTENSION
        
        # Create signature data structure
        signature_data = {
            "format_version": "1.0",
            "algorithm": self.ALGORITHM,
            "key_size": key_size,
            "timestamp": datetime.now().isoformat(),
            "original_filename": FileHandler.get_filename(original_filepath),
            "signature": base64.b64encode(signature).decode('utf-8')
        }
        
        # Write signature file
        FileHandler.write_text_to_file(output_path, json.dumps(signature_data, indent=2))
        
        return output_path

    def load_signature_file(self, signature_filepath: str) -> Dict[str, Any]:
        """
        Load and parse a signature file.
        
        Args:
            signature_filepath: Path to the signature file
            
        Returns:
            Dictionary containing signature data and metadata
            
        Raises:
            FileNotFoundError: If signature file doesn't exist
            ValueError: If signature file format is invalid
        """
        if not FileHandler.file_exists(signature_filepath):
            raise FileNotFoundError(f"Signature file not found: {signature_filepath}")
        
        try:
            content = FileHandler.read_text_from_file(signature_filepath)
            signature_data = json.loads(content)
            
            # Validate required fields
            required_fields = ["algorithm", "signature"]
            for field in required_fields:
                if field not in signature_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Decode signature from base64
            signature_data["signature_bytes"] = base64.b64decode(
                signature_data["signature"].encode('utf-8')
            )
            
            return signature_data
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid signature file format: {e}")

    def get_signature_bytes(self, signature_filepath: str) -> bytes:
        """
        Extract just the signature bytes from a signature file.
        
        Args:
            signature_filepath: Path to the signature file
            
        Returns:
            Digital signature as bytes
        """
        data = self.load_signature_file(signature_filepath)
        return data["signature_bytes"]

    def get_signature_info(self, signature_filepath: str) -> Dict[str, Any]:
        """
        Get metadata from a signature file (without the actual signature bytes).
        
        Args:
            signature_filepath: Path to the signature file
            
        Returns:
            Dictionary with signature metadata
        """
        data = self.load_signature_file(signature_filepath)
        
        # Return metadata without raw signature data
        return {
            "format_version": data.get("format_version", "Unknown"),
            "algorithm": data.get("algorithm", "Unknown"),
            "key_size": data.get("key_size", "Unknown"),
            "timestamp": data.get("timestamp", "Unknown"),
            "original_filename": data.get("original_filename", "Unknown")
        }

    def format_verification_result(
        self,
        is_valid: bool,
        signature_info: Dict[str, Any],
        filepath: str
    ) -> str:
        """
        Format verification result for display.
        
        Args:
            is_valid: Whether the signature is valid
            signature_info: Metadata from signature file
            filepath: Path to the verified file
            
        Returns:
            Formatted verification result string
        """
        if is_valid:
            result = f"""
✓ Signature is VALID

File: {FileHandler.get_filename(filepath)}
Algorithm: {signature_info.get('algorithm', 'Unknown')}
Key Size: {signature_info.get('key_size', 'Unknown')} bits
Signed On: {signature_info.get('timestamp', 'Unknown')}
Original Filename: {signature_info.get('original_filename', 'Unknown')}

The file has not been modified since it was signed.
"""
        else:
            result = f"""
✗ Signature is INVALID

File: {FileHandler.get_filename(filepath)}
Algorithm: {signature_info.get('algorithm', 'Unknown')}
Key Size: {signature_info.get('key_size', 'Unknown')} bits

WARNING: The file may have been tampered with or the signature
was created with a different key!
"""
        return result

    @staticmethod
    def is_signature_file(filepath: str) -> bool:
        """
        Check if a file is a signature file.
        
        Args:
            filepath: Path to check
            
        Returns:
            True if file has .sig extension
        """
        return filepath.lower().endswith(SignatureManager.SIGNATURE_EXTENSION)

    @staticmethod
    def get_original_file_path(signature_filepath: str) -> str:
        """
        Get the original file path from a signature file path.
        
        Args:
            signature_filepath: Path to signature file
            
        Returns:
            Path to original file (without .sig extension)
        """
        if signature_filepath.lower().endswith(SignatureManager.SIGNATURE_EXTENSION):
            return signature_filepath[:-len(SignatureManager.SIGNATURE_EXTENSION)]
        return signature_filepath


if __name__ == "__main__":
    # Test SignatureManager
    print("Testing SignatureManager...")
    
    sm = SignatureManager()
    
    # Create a test signature file
    test_signature = b"This is a test signature data"
    test_filepath = "test_document.txt"
    
    # Create signature file
    sig_path = sm.create_signature_file(
        original_filepath=test_filepath,
        signature=test_signature,
        key_size=2048
    )
    print(f"Created signature file: {sig_path}")
    
    # Load signature file
    sig_data = sm.load_signature_file(sig_path)
    print(f"\nLoaded signature data:")
    print(f"  Algorithm: {sig_data.get('algorithm')}")
    print(f"  Key Size: {sig_data.get('key_size')}")
    print(f"  Timestamp: {sig_data.get('timestamp')}")
    print(f"  Original File: {sig_data.get('original_filename')}")
    
    # Get signature bytes
    sig_bytes = sm.get_signature_bytes(sig_path)
    print(f"\nSignature bytes match: {sig_bytes == test_signature}")
    
    # Get signature info
    info = sm.get_signature_info(sig_path)
    print(f"\nSignature info: {info}")
    
    # Format verification result
    result = sm.format_verification_result(True, info, test_filepath)
    print(result)
    
    # Cleanup
    os.remove(sig_path)
    print("Cleaned up test files")
