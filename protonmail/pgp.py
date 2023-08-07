"""PGP."""
import os
from base64 import b64decode, b64encode
from io import IOBase

from Crypto.Cipher import AES
from pgpy import PGPMessage, PGPKey
from playwright.sync_api import sync_playwright


current_dir = os.path.dirname(os.path.abspath(__file__))
path_to_pgp_js = f"file:///{current_dir}/utils/openpgp.html"


class PGP:
    """PGP"""
    @staticmethod
    def create_message(blob: any):
        """Create new pgp message from blob."""
        return PGPMessage.new(blob)

    @staticmethod
    def message(blob: any) -> PGPMessage:
        """Load pgp message from blob."""
        return PGPMessage.from_blob(blob)

    @staticmethod
    def key(blob: any) -> PGPKey:
        """Load pgp key from blob."""
        return PGPKey.from_blob(blob)

    @staticmethod
    def aes256_decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt AES256."""
        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        cipher = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
        decrypted_data = cipher.decrypt(data)[18:-22]

        return decrypted_data

    @staticmethod
    def aes_encrypt(message: str, session_key: bytes = None):
        """Encrypt AES256."""
        if not session_key:
            session_key = os.urandom(32)

        iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        cipher = AES.new(session_key, AES.MODE_CFB, iv, segment_size=128)
        encrypted_message = cipher.encrypt(message.encode())
        body_key = b64encode(session_key)

        return encrypted_message, body_key

    def __init__(self):
        self.public_key = ''
        self.private_key = ''
        self.passphrase = ''
        self.session_key = b''
        self.aes256_keys = {}

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

    def decrypt(self, data: str, private_key: str = None, passphrase: str = None) -> str:
        """Decrypt pgp with private key & passphrase."""
        if not private_key:
            private_key = self.private_key
        if not passphrase:
            passphrase = self.passphrase

        pgp_private_key, _ = self.key(private_key)
        encrypted_message = self.message(data)

        with pgp_private_key.unlock(passphrase) as key:
            message = key.decrypt(encrypted_message).message

        return message

    def encrypt(self, data: str, public_key: str = None) -> str:
        """Encrypt pgp with public key."""
        if not public_key:
            public_key = self.public_key

        public_key, _ = self.key(public_key)
        message = self.create_message(data)
        encrypted_message = str(public_key.encrypt(message))

        return encrypted_message

    def decrypt_session_key(self, encrypted_key: str) -> bytes:
        """Decrypt session key with OpenPG.js"""
        if self.aes256_keys.get(encrypted_key):
            return self.aes256_keys[encrypted_key]

        with sync_playwright() as context:
            browser = context.webkit.launch()
            page = browser.new_page()
            page.goto(path_to_pgp_js)

            raw_encrypted_key = list(b64decode(encrypted_key))
            args = [self.private_key, self.passphrase, raw_encrypted_key]

            aes256_keys = page.evaluate(f'decryptSessionKeys({args})')
            aes256_key = bytes(aes256_keys[0]['data'].values())

            browser.close()

        return aes256_key

    def encrypt_with_session_key(self, message: str, session_key: bytes = None) -> tuple[bytes, bytes]:
        """Encrypt message with session key with OpenPG.js"""
        if not session_key:
            session_key = os.urandom(32)

        with sync_playwright() as context:
            browser = context.webkit.launch()
            page = browser.new_page()
            page.goto(path_to_pgp_js)

            args = [
                self.private_key,
                self.passphrase,
                list(session_key),
                message
            ]

            encrypted_message = page.evaluate(f'encryptMessage({args})')
            body_message = bytes(encrypted_message.values())

            browser.close()

        return body_message, session_key

    def js_decrypt_message(self, data: str) -> str:
        """Decrypt pgp message with OpenPG.js"""
        with sync_playwright() as context:
            browser = context.webkit.launch()
            page = browser.new_page()
            page.goto(path_to_pgp_js)

            args = [data, self.private_key, self.passphrase]

            decrypted_message = page.evaluate(f'decryptMessage({args})')
            decrypted_message = bytes(decrypted_message['data'].values()).decode()

            browser.close()

        return decrypted_message
