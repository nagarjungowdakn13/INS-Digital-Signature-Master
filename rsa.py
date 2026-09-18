"""
RSA Algorithm Implementation

This module provides an RSA implementation for digital signature
applications including key generation, encryption, and decryption.
"""

import random
import secrets
from typing import Tuple, Optional


class RSA:
    """RSA cryptographic algorithm implementation."""

    def __init__(self, key_length: int = 1024):
        """
        Initialize RSA with key generation.
        
        Args:
            key_length: Length of the RSA key in bits (1024, 2048, or 4096)
        """
        self.key_length = key_length
        self.p: int = 0
        self.q: int = 0
        self.n: int = 0
        self.lambda_n: int = 0
        self.e: int = 0
        self.d: int = 0
        self.public_key: Tuple[int, int] = (0, 0)
        self.private_key: Tuple[int, int] = (0, 0)
        
        self._generate_keys()

    @staticmethod
    def _is_prime(n: int, k: int = 40) -> bool:
        """
        Miller-Rabin primality test.
        
        Args:
            n: Number to test for primality
            k: Number of rounds of testing
            
        Returns:
            True if n is probably prime, False otherwise
        """
        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 as 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2

        # Witness loop
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True

    def _generate_prime(self, bits: int) -> int:
        """
        Generate a random prime number of specified bit length.
        
        Args:
            bits: Bit length of the prime
            
        Returns:
            A prime number of the specified bit length
        """
        while True:
            # Generate a random odd number of the specified bit length
            candidate = secrets.randbits(bits)
            candidate |= (1 << (bits - 1)) | 1  # Ensure it's odd and has correct bit length
            
            if self._is_prime(candidate):
                return candidate

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        """Compute greatest common divisor using Euclidean algorithm."""
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def _mod_inverse(a: int, m: int) -> int:
        """
        Compute modular multiplicative inverse using extended Euclidean algorithm.
        
        Args:
            a: Number to find inverse of
            m: Modulus
            
        Returns:
            Modular inverse of a mod m
        """
        if RSA._gcd(a, m) != 1:
            raise ValueError("Modular inverse does not exist")
        
        # Extended Euclidean Algorithm
        m0, x0, x1 = m, 0, 1
        
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        
        return x1 + m0 if x1 < 0 else x1

    def _generate_keys(self) -> None:
        """Generate RSA public and private key pairs."""
        # Generate two distinct large primes p and q, each half the
        # requested key length so that n = p * q has the requested bit length
        prime_bits = self.key_length // 2
        self.p = self._generate_prime(prime_bits)
        self.q = self._generate_prime(prime_bits)

        # Ensure p and q are different
        while self.p == self.q:
            self.q = self._generate_prime(prime_bits)
        
        # Compute n = p * q
        self.n = self.p * self.q
        
        # Compute λ(n) = lcm(p-1, q-1) = (p-1)(q-1)/gcd(p-1, q-1)
        # For simplicity, using Euler's totient φ(n) = (p-1)(q-1)
        phi_n = (self.p - 1) * (self.q - 1)
        self.lambda_n = phi_n
        
        # Choose e: 1 < e < λ(n) and gcd(e, λ(n)) = 1
        # Common choice is 65537 (2^16 + 1) as it's prime and efficient
        self.e = 65537
        if self._gcd(self.e, self.lambda_n) != 1:
            # If 65537 doesn't work, find another suitable e
            self.e = self._generate_prime(self.key_length // 2)
            while self._gcd(self.e, self.lambda_n) != 1:
                self.e = self._generate_prime(self.key_length // 2)
        
        # Compute d: d ≡ e^(-1) (mod λ(n))
        self.d = self._mod_inverse(self.e, self.lambda_n)
        
        # Public key: (e, n)
        self.public_key = (self.e, self.n)
        
        # Private key: (d, n)
        self.private_key = (self.d, self.n)

    def encrypt(self, message: bytes, key: Optional[Tuple[int, int]] = None) -> bytes:
        """
        Encrypt/Sign message using RSA.
        
        For signing, use the private key.
        For encryption, use the public key.
        
        Args:
            message: Message to encrypt as bytes
            key: Tuple of (exponent, modulus), defaults to private key
            
        Returns:
            Encrypted message as bytes
        """
        if key is None:
            key = self.private_key

        exp, mod = key

        # Convert message bytes to integer
        m = int.from_bytes(message, byteorder='big')
        if m >= mod:
            raise ValueError("Message is too large for the RSA key size")

        # Encrypt: c = m^exp mod n
        c = pow(m, exp, mod)

        # Convert back to bytes, padded to the modulus size so the output
        # length is always fixed regardless of the numeric value of c
        byte_length = (mod.bit_length() + 7) // 8
        return c.to_bytes(byte_length, byteorder='big')

    def decrypt(self, ciphertext: bytes, key: Optional[Tuple[int, int]] = None,
                output_length: Optional[int] = None) -> bytes:
        """
        Decrypt/Verify message using RSA.

        For verification, use the public key.
        For decryption, use the private key.

        Args:
            ciphertext: Encrypted message as bytes
            key: Tuple of (exponent, modulus), defaults to public key
            output_length: Exact byte length of the recovered plaintext.
                Required when the plaintext may contain leading zero bytes
                (e.g. verifying a fixed-length hash), otherwise the minimal
                encoding is used.

        Returns:
            Decrypted message as bytes
        """
        if key is None:
            key = self.public_key

        exp, mod = key

        # Convert ciphertext bytes to integer
        c = int.from_bytes(ciphertext, byteorder='big')

        # Decrypt: m = c^exp mod n
        m = pow(c, exp, mod)

        # Convert back to bytes
        if output_length is None:
            output_length = (m.bit_length() + 7) // 8
        return m.to_bytes(output_length, byteorder='big')

    def sign(self, hash_bytes: bytes) -> bytes:
        """
        Create digital signature by encrypting hash with private key.
        
        Args:
            hash_bytes: Hash of the message to sign
            
        Returns:
            Digital signature as bytes
        """
        return self.encrypt(hash_bytes, self.private_key)

    def verify_signature(self, signature: bytes, expected_hash: bytes) -> bool:
        """
        Verify digital signature by decrypting with public key and comparing.
        
        Args:
            signature: The digital signature to verify
            expected_hash: The expected hash value
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            decrypted_hash = self.decrypt(signature, self.public_key,
                                           output_length=len(expected_hash))
            return decrypted_hash == expected_hash
        except Exception:
            return False

    def get_public_key(self) -> Tuple[int, int]:
        """Return the public key (e, n)."""
        return self.public_key

    def get_private_key(self) -> Tuple[int, int]:
        """Return the private key (d, n)."""
        return self.private_key

    def set_keys(self, public_key: Tuple[int, int], private_key: Tuple[int, int]) -> None:
        """
        Set existing keys (for loading saved keys).
        
        Args:
            public_key: Tuple of (e, n)
            private_key: Tuple of (d, n)
        """
        self.public_key = public_key
        self.private_key = private_key
        self.e, self.n = public_key
        self.d, _ = private_key

    @staticmethod
    def bytes_to_hex(data: bytes) -> str:
        """Convert bytes to hexadecimal string."""
        return data.hex().upper()

    @staticmethod
    def hex_to_bytes(hex_string: str) -> bytes:
        """Convert hexadecimal string to bytes."""
        return bytes.fromhex(hex_string)


if __name__ == "__main__":
    # Test RSA implementation
    print("Testing RSA implementation...")
    print("-" * 50)
    
    rsa = RSA(key_length=1024)
    
    print(f"Key length: 1024 bits")
    print(f"Public key (e): {rsa.public_key[0]}")
    print(f"Modulus (n) [first 50 chars]: {str(rsa.public_key[1])[:50]}...")
    print()
    
    # Test encryption/decryption
    test_message = b"Hello, RSA!"
    print(f"Original message: {test_message}")
    
    encrypted = rsa.encrypt(test_message, rsa.public_key)
    print(f"Encrypted (hex): {encrypted.hex()[:50]}...")
    
    decrypted = rsa.decrypt(encrypted, rsa.private_key)
    print(f"Decrypted: {decrypted}")
    
    print(f"\nEncryption/Decryption test: {'PASSED' if test_message == decrypted else 'FAILED'}")
    
    # Test signing/verification
    print("\n" + "-" * 50)
    print("Testing digital signature...")
    
    from sha256 import SHA256
    sha = SHA256()
    message_hash = sha.hash(b"test message")
    
    signature = rsa.sign(message_hash)
    print(f"Signature created (hex): {signature.hex()[:50]}...")
    
    is_valid = rsa.verify_signature(signature, message_hash)
    print(f"Signature verification: {'VALID' if is_valid else 'INVALID'}")
