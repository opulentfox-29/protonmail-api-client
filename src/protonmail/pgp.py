"""PGP."""

import os
from base64 import b64decode, b64encode
from io import IOBase
from typing import Union, Optional

from Crypto.Cipher import AES
from pgpy import PGPMessage, PGPKey


class PGP:
    """PGP"""
    def __init__(self):
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.public_key = str()
        self.private_key = str()
        self.passphrase = str()
        self.aes256_keys = dict()

    def import_pgp(self, private_key: str, passphrase: str) -> None:
        """Import pgp private key and passphrase."""
        self.passphrase = passphrase

        if isinstance(private_key, IOBase):
            self.private_key = private_key.read()

        elif os.path.isfile(private_key):
            with open(private_key, 'r', encoding='utf-8') as file:
                self.private_key = file.read()

        else:
            self.private_key = private_key

    def decrypt(self, data: str, private_key: Optional[str] = None, passphrase: Optional[str] = None) -> str:
        """Decrypt pgp with private key & passphrase."""
        if not private_key:
            private_key = self.private_key
        if not passphrase:
            passphrase = self.passphrase

        pgp_private_key, _ = self.key(private_key)
        encrypted_message = self.message(data)

        with pgp_private_key.unlock(passphrase) as key:
            message = key.decrypt(encrypted_message).message

        # Some messages are encoded in latin_1, so we will recode them in utf-8
        try:
            if not isinstance(message, str):
                message = message.decode('utf-8')
            message = message.encode('latin_1').decode('utf-8')
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass

        return message

    def encrypt(self, data: str, public_key: Optional[str] = None) -> str:
        """Encrypt pgp with public key."""
        if not public_key:
            public_key = self.public_key

        public_key, _ = self.key(public_key)
        message = self.create_message(data)
        encrypted_message = str(public_key.encrypt(message))

        return encrypted_message

    def decrypt_session_key(self, encrypted_key: str) -> bytes:
        """Decrypt session key."""
        if self.aes256_keys.get(encrypted_key):
            return self.aes256_keys[encrypted_key]

        pgp_private_key, _ = self.key(self.private_key)
        encrypted_message = self.message(b64decode(encrypted_key))

        with pgp_private_key.unlock(self.passphrase) as key:
            subkey = tuple(dict(key.subkeys).values())[0]
            pkesk = encrypted_message._sessionkeys[0]
            alg, aes256_key = pkesk.decrypt_sk(subkey._key)

        return aes256_key

    def encrypt_with_session_key(self, message: str, session_key: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Encrypt message with session key"""
        if not session_key:
            session_key = os.urandom(32)

        pgp_message = self.create_message(message)

        pgp_private_key, _ = self.key(self.private_key)
        with pgp_private_key.unlock(self.passphrase) as key:
            pgp_message |= key.sign(pgp_message)

        encrypted_message = pgp_message.encrypt(self.passphrase, session_key)

        lines_encrypted_message_pgp = str(encrypted_message).split('\n')
        del lines_encrypted_message_pgp[2]  # delete information from PGPy (OpenPGP.js doesn't have it), ProtonMail doesn't work with it
        encrypted_message_pgp = '\n'.join(lines_encrypted_message_pgp)
        encrypted_message = self.message(encrypted_message_pgp)

        return bytes(encrypted_message), session_key

    def aes256_decrypt(self, data: bytes, key: bytes) -> Union[bytes, int]:
        """Decrypt AES256."""
        cipher = AES.new(key, AES.MODE_CFB, self.iv, segment_size=128)
        decrypted_data = cipher.decrypt(data)[18:-22]

        return decrypted_data

    def aes256_encrypt(self, message: str, session_key: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Encrypt AES256."""
        if not session_key:
            session_key = os.urandom(32)

        cipher = AES.new(session_key, AES.MODE_CFB, self.iv, segment_size=128)
        binary_message = message.encode() if isinstance(message, str) else message
        encrypted_message = cipher.encrypt(binary_message)
        body_key = b64encode(session_key)

        return encrypted_message, body_key

    @staticmethod
    def create_message(blob: any):
        """Create new pgp message from blob."""
        return PGPMessage.new(blob, compression=False)

    @staticmethod
    def message(blob: any) -> PGPMessage:
        """Load pgp message from blob."""
        return PGPMessage.from_blob(blob)

    @staticmethod
    def key(blob: any) -> PGPKey:
        """Load pgp key from blob."""
        return PGPKey.from_blob(blob)
