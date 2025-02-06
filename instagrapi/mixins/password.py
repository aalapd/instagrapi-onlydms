import base64
import os
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class PasswordMixin:
    def password_encrypt(self, password: str) -> str:
        # Get public key parameters from Instagram
        publickeyid, publickey = self.password_publickeys()

        # Generate a random 32‐byte session key and a 12‐byte IV
        session_key = os.urandom(32)
        iv = os.urandom(12)

        # Get the current timestamp (as a string)
        timestamp = str(int(time.time()))

        # Decode the base64‑encoded public key and load it.
        decoded_publickey = base64.b64decode(publickey.encode())
        try:
            recipient_key = serialization.load_der_public_key(decoded_publickey)
        except Exception:
            recipient_key = serialization.load_pem_public_key(decoded_publickey)

        # RSA‑encrypt the session key using PKCS1v15 padding.
        rsa_encrypted = recipient_key.encrypt(
            session_key,
            padding.PKCS1v15()
        )

        # Use AES-GCM for authenticated encryption of the password.
        aesgcm = AESGCM(session_key)
        # Use the timestamp (as bytes) as additional authenticated data.
        aad = timestamp.encode("utf8")
        # Encrypt the password; AESGCM.encrypt returns ciphertext concatenated with a 16-byte tag.
        encrypted_data = aesgcm.encrypt(iv, password.encode("utf8"), aad)
        # Separate the ciphertext and the tag.
        ciphertext = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        # Prepare a 2-byte little-endian representation of the RSA-encrypted key length.
        size_buffer = len(rsa_encrypted).to_bytes(2, byteorder="little")

        # Assemble the payload in the required order:
        #  • 1 byte: version marker (0x01)
        #  • 1 byte: public key id (big endian)
        #  • 12 bytes: IV
        #  • 2 bytes: length of RSA encrypted key (little endian)
        #  • RSA encrypted session key
        #  • 16 bytes: AES-GCM tag
        #  • Remaining bytes: AES ciphertext of the password
        payload = b"".join([
            b"\x01",
            publickeyid.to_bytes(1, byteorder="big"),
            iv,
            size_buffer,
            rsa_encrypted,
            tag,
            ciphertext
        ])

        # Base64 encode the payload.
        payload_b64 = base64.b64encode(payload).decode("utf8")

        # Return the final formatted string.
        return f"#PWD_INSTAGRAM:4:{timestamp}:{payload_b64}"

    def password_publickeys(self):
        resp = self.public.get("https://i.instagram.com/api/v1/qe/sync/")
        publickeyid = int(resp.headers.get("ig-set-password-encryption-key-id"))
        publickey = resp.headers.get("ig-set-password-encryption-pub-key")
        return publickeyid, publickey
