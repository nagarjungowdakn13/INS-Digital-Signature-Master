"""
File Handler Module

This module provides file operations for reading and writing files
for digital signature operations.
"""

import os
from typing import Optional


class FileHandler:
    """Handle file reading and writing operations."""

    @staticmethod
    def read_file_as_bytes(filepath: str) -> bytes:
        """
        Read file content as bytes.
        
        Args:
            filepath: Path to the file to read
            
        Returns:
            File content as bytes
            
        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be read
            IOError: For other I/O errors
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        if not os.path.isfile(filepath):
            raise ValueError(f"Path is not a file: {filepath}")
        
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except PermissionError:
            raise PermissionError(f"Permission denied reading file: {filepath}")
        except IOError as e:
            raise IOError(f"Error reading file {filepath}: {e}")

    @staticmethod
    def write_bytes_to_file(filepath: str, data: bytes) -> None:
        """
        Write bytes to a file.
        
        Args:
            filepath: Path to the file to write
            data: Bytes to write to the file
            
        Raises:
            PermissionError: If file cannot be written
            IOError: For other I/O errors
        """
        # Create directory if it doesn't exist
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
        except PermissionError:
            raise PermissionError(f"Permission denied writing file: {filepath}")
        except IOError as e:
            raise IOError(f"Error writing file {filepath}: {e}")

    @staticmethod
    def write_text_to_file(filepath: str, text: str) -> None:
        """
        Write text to a file.
        
        Args:
            filepath: Path to the file to write
            text: Text to write to the file
        """
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(text)
        except PermissionError:
            raise PermissionError(f"Permission denied writing file: {filepath}")
        except IOError as e:
            raise IOError(f"Error writing file {filepath}: {e}")

    @staticmethod
    def read_text_from_file(filepath: str) -> str:
        """
        Read text from a file.
        
        Args:
            filepath: Path to the file to read
            
        Returns:
            File content as string
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except PermissionError:
            raise PermissionError(f"Permission denied reading file: {filepath}")
        except IOError as e:
            raise IOError(f"Error reading file {filepath}: {e}")

    @staticmethod
    def file_exists(filepath: str) -> bool:
        """
        Check if a file exists.
        
        Args:
            filepath: Path to check
            
        Returns:
            True if file exists, False otherwise
        """
        return os.path.isfile(filepath)

    @staticmethod
    def get_file_size(filepath: str) -> int:
        """
        Get file size in bytes.
        
        Args:
            filepath: Path to the file
            
        Returns:
            File size in bytes
        """
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        return os.path.getsize(filepath)

    @staticmethod
    def get_filename(filepath: str) -> str:
        """
        Get filename from path.
        
        Args:
            filepath: Full path to file
            
        Returns:
            Filename without directory
        """
        return os.path.basename(filepath)

    @staticmethod
    def get_signature_filepath(original_filepath: str) -> str:
        """
        Generate signature file path from original file path.
        
        Args:
            original_filepath: Path to the original file
            
        Returns:
            Path for the signature file (.sig extension)
        """
        return original_filepath + ".sig"

    @staticmethod
    def ensure_directory_exists(dirpath: str) -> None:
        """
        Ensure a directory exists, creating it if necessary.
        
        Args:
            dirpath: Path to the directory
        """
        if dirpath and not os.path.exists(dirpath):
            os.makedirs(dirpath)

    @staticmethod
    def get_absolute_path(filepath: str) -> str:
        """
        Convert relative path to absolute path.
        
        Args:
            filepath: Relative or absolute path
            
        Returns:
            Absolute path
        """
        return os.path.abspath(filepath)


if __name__ == "__main__":
    # Test FileHandler
    print("Testing FileHandler...")
    
    # Test file operations
    test_file = "test_file.txt"
    test_content = b"Hello, this is a test file!"
    
    # Write test file
    FileHandler.write_bytes_to_file(test_file, test_content)
    print(f"Wrote {len(test_content)} bytes to {test_file}")
    
    # Read test file
    read_content = FileHandler.read_file_as_bytes(test_file)
    print(f"Read {len(read_content)} bytes from {test_file}")
    print(f"Content match: {read_content == test_content}")
    
    # Get signature path
    sig_path = FileHandler.get_signature_filepath(test_file)
    print(f"Signature path: {sig_path}")
    
    # Cleanup
    os.remove(test_file)
    print(f"Cleaned up test file")
