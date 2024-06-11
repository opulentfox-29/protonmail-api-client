"""PGP."""
import os
from base64 import b64decode, b64encode
from io import IOBase
from typing import Union, Optional

import requests
from Crypto.Cipher import AES
from pgpy import PGPMessage, PGPKey
from playwright.sync_api import sync_playwright

from .constants import open_pgp_js_url, utils_path


class PGP:
    """PGP"""
    def __init__(self):
        self.pgp_html_url = f'file:///{utils_path}/openpgp.html'
        self.open_pgp_js_path = f'{utils_path}/openpgp.js'
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.public_key = ''
        self.private_key = ''
        self.passphrase = ''
        self.session_key = b''
        self.aes256_keys = {}

        self.__check_js_openpgp()

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
        """Decrypt session key with OpenPGP.js"""
        if self.aes256_keys.get(encrypted_key):
            return self.aes256_keys[encrypted_key]

        with sync_playwright() as context:
            browser = context.webkit.launch()
            page = browser.new_page()
            page.goto(self.pgp_html_url)

            raw_encrypted_key = list(b64decode(encrypted_key))
            args = [self.private_key, self.passphrase, raw_encrypted_key]

            aes256_keys = page.evaluate(f'decryptSessionKeys({args})')
            aes256_key = bytes(aes256_keys[0]['data'].values())

            browser.close()

        return aes256_key

    def encrypt_with_session_key(self, message: str, session_key: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Encrypt message with session key with OpenPGP.js"""
        if not session_key:
            session_key = os.urandom(32)

        with sync_playwright() as context:
            browser = context.webkit.launch()
            page = browser.new_page()
            page.goto(self.pgp_html_url)

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

    def aes256_decrypt(self, data: bytes, key: bytes) -> Union[bytes, int]:
        """Decrypt AES256."""
        cipher = AES.new(key, AES.MODE_CFB, self.iv, segment_size=128)
        decrypted_data = cipher.decrypt(data)[18:-22]

        return decrypted_data

    def aes_encrypt(self, message: str, session_key: Optional[bytes] = None) -> tuple[bytes, bytes]:
        """Encrypt AES256."""
        if not session_key:
            session_key = os.urandom(32)

        cipher = AES.new(session_key, AES.MODE_CFB, self.iv, segment_size=128)
        encrypted_message = cipher.encrypt(message.encode())
        body_key = b64encode(session_key)

        return encrypted_message, body_key

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

    def __check_js_openpgp(self):
        if not os.path.isfile(self.open_pgp_js_path):
            self.__download_js_openpgp()

    def __download_js_openpgp(self):
        response = requests.get(open_pgp_js_url)

        with open(self.open_pgp_js_path, 'w', encoding='utf-8') as f:
            f.write(response.text)
            