"""PGP."""

import os
import warnings
from base64 import b64decode, b64encode
from typing import Union, Optional

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pgpy import PGPMessage, PGPKey

from protonmail.exceptions import NoKeysForDecryptThisMessage
from protonmail.models import PgpPairKeys


warnings.filterwarnings("ignore", module="pgpy")  # ignore deprecation warnings for pgpy


class PGP:
    """PGP"""
    def __init__(self):
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.pairs_keys: list[PgpPairKeys] = list()
        self.aes256_keys = dict()

    def decrypt(self, data: str, private_key: Optional[str] = None, passphrase: Optional[str] = None) -> str:
        """Decrypt pgp with private key & passphrase."""
        encrypted_message = self.message(data)

        if not private_key:
            fingerprint = self._get_public_fingerprint_from_message(encrypted_message)
            pair = self._get_pair_keys(fingerprint=fingerprint)
            if pair is None:
                raise NoKeysForDecryptThisMessage(NoKeysForDecryptThisMessage.__doc__, 'you need private key for public key:', fingerprint)
            private_key = pair.private_key
            passphrase = pair.passphrase

        pgp_private_key, _ = self.key(private_key)
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
            public_key = self._get_pair_keys(is_primary=True).public_key

        public_key, _ = self.key(public_key)
        message = self.create_message(data)
        encrypted_message = str(public_key.encrypt(message))

        return encrypted_message

    def decrypt_session_key(self, encrypted_key: str) -> bytes:
        """Decrypt session key."""
        if self.aes256_keys.get(encrypted_key):
            return self.aes256_keys[encrypted_key]

        encrypted_message = self.message(b64decode(encrypted_key))
        fingerprint = self._get_public_fingerprint_from_message(encrypted_message)
        pair_keys = self._get_pair_keys(fingerprint=fingerprint)
        pgp_private_key, _ = self.key(pair_keys.private_key)

        with pgp_private_key.unlock(pair_keys.passphrase) as key:
            subkey = tuple(dict(key.subkeys).values())[0]
            pkesk = encrypted_message._sessionkeys[0]
            alg, aes256_key = pkesk.decrypt_sk(subkey._key)

        return aes256_key

    def encrypt_session_key(self, session_key: bytes, public_key: Optional[Union[str, PGPKey]] = None) -> bytes:
        """Encrypt session key."""
        if not public_key:
            public_key = self._get_pair_keys(is_primary=True).public_key
        if isinstance(public_key, str):
            public_key, _ = self.key(public_key)

        message = self.create_message('message for encrypt')
        encrypted_message = public_key.encrypt(message, sessionkey=session_key)
        encrypted_session_key = bytes(encrypted_message._sessionkeys[0])

        return encrypted_session_key

    def encrypt_with_session_key(self, message: str, session_key: Optional[bytes] = None) -> tuple[bytes, bytes, bytes]:
        """Encrypt message with session key"""
        if not session_key:
            session_key = os.urandom(32)

        pgp_message = self.create_message(message)

        pair_keys = self._get_pair_keys(is_primary=True)
        pgp_private_key, _ = self.key(pair_keys.private_key)
        with pgp_private_key.unlock(pair_keys.passphrase) as key:
            pgp_message |= key.sign(pgp_message)
        signature = bytes(pgp_message.signatures[0])

        encrypted_message = pgp_message.encrypt(pair_keys.passphrase, session_key)

        lines_encrypted_message_pgp = str(encrypted_message).split('\n')
        del lines_encrypted_message_pgp[2]  # delete information from PGPy (OpenPGP.js doesn't have it), ProtonMail doesn't work with it
        encrypted_message_pgp = '\n'.join(lines_encrypted_message_pgp)
        encrypted_message = self.message(encrypted_message_pgp)

        return bytes(encrypted_message), session_key, signature

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

    def aes_gcm_encrypt(self, message: str, session_key: Optional[bytes] = None) -> bytes:
        """Encrypt AES GCM."""
        if not session_key:
            session_key = os.urandom(32)
        iv = os.urandom(16)

        aesgcm = AESGCM(session_key)
        binary_message = message.encode() if isinstance(message, str) else message
        encrypted_message = aesgcm.encrypt(iv, binary_message, None)

        iv_and_message = iv + encrypted_message

        return iv_and_message

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

    def _get_pair_keys(self, fingerprint: Optional[str] = None, is_primary: Optional[bool] = None, is_user_key: bool = False) -> Optional[PgpPairKeys]:
        for pair in self.pairs_keys:
            if is_primary is not None and is_primary != pair.is_primary:
                continue
            if pair.is_user_key != is_user_key:
                continue
            fingerprint_public = pair.fingerprint_public or str()
            fingerprint_private = pair.fingerprint_private or str()
            if fingerprint is not None and fingerprint[-16:].upper() not in (fingerprint_public[-16:].upper(), fingerprint_private[-16:].upper()):
                continue
            return pair
        return None

    def _get_public_fingerprint_from_message(self, message: PGPMessage) -> str:
        fingerprint = list(message.issuers)[0]
        return fingerprint
