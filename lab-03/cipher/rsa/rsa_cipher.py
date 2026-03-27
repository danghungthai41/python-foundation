import rsa
import os

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

class RSACipher:
    def generate_keys(self):
        """Generate RSA key pair and save to PEM files."""
        (public_key, private_key) = rsa.newkeys(2048)
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(private_key.save_pkcs1())
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(public_key.save_pkcs1())

    def load_keys(self):
        """Load keys from PEM files. Returns (private_key, public_key)."""
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = rsa.PrivateKey.load_pkcs1(f.read())
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = rsa.PublicKey.load_pkcs1(f.read())
        return private_key, public_key

    def encrypt(self, message: str, key) -> bytes:
        """Encrypt a plaintext message using the given RSA key."""
        return rsa.encrypt(message.encode("utf-8"), key)

    def decrypt(self, ciphertext: bytes, key) -> str:
        """Decrypt ciphertext using the given RSA private key."""
        return rsa.decrypt(ciphertext, key).decode("utf-8")

    def sign(self, message: str, private_key) -> bytes:
        """Sign a message using the private key (SHA-256)."""
        return rsa.sign(message.encode("utf-8"), private_key, "SHA-256")

    def verify(self, message: str, signature: bytes, public_key) -> bool:
        """Verify a signature using the public key. Returns True if valid."""
        try:
            rsa.verify(message.encode("utf-8"), signature, public_key)
            return True
        except rsa.VerificationError:
            return False