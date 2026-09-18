"""
SHA-256 Hashing Algorithm Implementation

This module provides a pure Python implementation of the SHA-256 
cryptographic hash function for digital signature applications.
"""

import struct


class SHA256:
    """SHA-256 hash function implementation."""
    
    # Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # Round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    def __init__(self):
        """Initialize SHA256 hasher."""
        pass

    @staticmethod
    def _right_rotate(value: int, amount: int) -> int:
        """Right rotate a 32-bit integer."""
        return ((value >> amount) | (value << (32 - amount))) & 0xffffffff

    @staticmethod
    def _preprocess(message: bytes) -> bytes:
        """
        Preprocess the message by padding it to a multiple of 512 bits.
        
        Args:
            message: The input message as bytes
            
        Returns:
            Padded message as bytes
        """
        length = len(message)
        bit_length = length * 8
        
        # Append bit '1' to message (0x80 = 10000000 in binary)
        message += b'\x80'
        
        # Append zeros until message length ≡ 448 (mod 512)
        # i.e., message length in bytes ≡ 56 (mod 64)
        while (len(message) % 64) != 56:
            message += b'\x00'
        
        # Append original length in bits as 64-bit big-endian integer
        message += struct.pack('>Q', bit_length)
        
        return message

    def hash(self, message: bytes) -> bytes:
        """
        Compute SHA-256 hash of the input message.
        
        Args:
            message: The input message as bytes
            
        Returns:
            32-byte hash digest
        """
        # Preprocess the message
        processed = self._preprocess(message)
        
        # Initialize hash values
        h = list(self.H)
        
        # Process each 512-bit (64-byte) chunk
        for i in range(0, len(processed), 64):
            chunk = processed[i:i + 64]
            
            # Create message schedule array
            w = [0] * 64
            
            # Copy chunk into first 16 words of message schedule
            for j in range(16):
                w[j] = struct.unpack('>I', chunk[j * 4:(j + 1) * 4])[0]
            
            # Extend the first 16 words into the remaining 48 words
            for j in range(16, 64):
                s0 = (self._right_rotate(w[j - 15], 7) ^
                      self._right_rotate(w[j - 15], 18) ^
                      (w[j - 15] >> 3))
                s1 = (self._right_rotate(w[j - 2], 17) ^
                      self._right_rotate(w[j - 2], 19) ^
                      (w[j - 2] >> 10))
                w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xffffffff
            
            # Initialize working variables
            a, b, c, d, e, f, g, hh = h
            
            # Main compression loop
            for j in range(64):
                S1 = (self._right_rotate(e, 6) ^
                      self._right_rotate(e, 11) ^
                      self._right_rotate(e, 25))
                ch = (e & f) ^ (~e & g)
                temp1 = (hh + S1 + ch + self.K[j] + w[j]) & 0xffffffff
                
                S0 = (self._right_rotate(a, 2) ^
                      self._right_rotate(a, 13) ^
                      self._right_rotate(a, 22))
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = (S0 + maj) & 0xffffffff
                
                hh = g
                g = f
                f = e
                e = (d + temp1) & 0xffffffff
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xffffffff
            
            # Add compressed chunk to current hash value
            h[0] = (h[0] + a) & 0xffffffff
            h[1] = (h[1] + b) & 0xffffffff
            h[2] = (h[2] + c) & 0xffffffff
            h[3] = (h[3] + d) & 0xffffffff
            h[4] = (h[4] + e) & 0xffffffff
            h[5] = (h[5] + f) & 0xffffffff
            h[6] = (h[6] + g) & 0xffffffff
            h[7] = (h[7] + hh) & 0xffffffff
        
        # Produce final hash value (big-endian)
        return b''.join(struct.pack('>I', val) for val in h)

    def hash_hex(self, message: bytes) -> str:
        """
        Compute SHA-256 hash and return as hexadecimal string.
        
        Args:
            message: The input message as bytes
            
        Returns:
            64-character hexadecimal hash string
        """
        return self.hash(message).hex().upper()


def sha256_hash(data: bytes) -> bytes:
    """
    Convenience function to compute SHA-256 hash.
    
    Args:
        data: Input data as bytes
        
    Returns:
        32-byte hash digest
    """
    return SHA256().hash(data)


def sha256_hash_hex(data: bytes) -> str:
    """
    Convenience function to compute SHA-256 hash as hex string.
    
    Args:
        data: Input data as bytes
        
    Returns:
        64-character hexadecimal hash string
    """
    return SHA256().hash_hex(data)


if __name__ == "__main__":
    # Test the SHA-256 implementation
    test_message = b"test"
    sha = SHA256()
    hash_result = sha.hash_hex(test_message)
    print(f"SHA-256 hash of 'test': {hash_result}")
    
    # Expected: 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
    expected = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08"
    print(f"Expected:               {expected}")
    print(f"Match: {hash_result == expected}")
