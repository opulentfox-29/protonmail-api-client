"""Utils downloaded from the official repository.
https://github.com/ProtonMail/proton-python-client/blob/master/proton/srp/util.py
https://github.com/ProtonMail/proton-python-client/blob/master/proton/srp/pmhash.py
"""

import base64
import hashlib
import os

import bcrypt
from typing_extensions import Self

from ..constants import SRP_LEN_BYTES


class PMHash:
    """Custom expanded version of SHA512"""

    def __init__(self, binary: bytes = b''):
        self.binary = binary

    def update(self, binary: bytes) -> None:
        self.binary += binary

    def digest(self) -> bytes:
        return b''.join([
            hashlib.sha512(self.binary + b'\0').digest(),
            hashlib.sha512(self.binary + b'\1').digest(),
            hashlib.sha512(self.binary + b'\2').digest(),
            hashlib.sha512(self.binary + b'\3').digest()
        ])


def pm_hash(binary: bytes = b'') -> object:
    return PMHash(binary)


def bcrypt_b64_encode(binary: bytes) -> bytes:
    bcrypt_base64 = b'./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'  # noqa
    std_base64chars = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'  # noqa
    binary = base64.b64encode(binary)
    return binary.translate(bytes.maketrans(std_base64chars, bcrypt_base64))


def hash_password(hash_class: callable, password: bytes, salt: bytes, modulus: bytes) -> bytes:
    salt = (salt + b'proton')[:16]
    salt = bcrypt_b64_encode(salt)[:22]
    hashed = bcrypt.hashpw(password, b'$2y$10$' + salt)
    return hash_class(hashed + modulus).digest()


def bytes_to_long(binary: bytes) -> int:
    return int.from_bytes(binary, 'little')


def long_to_bytes(num: int, num_bytes: int) -> bytes:
    return num.to_bytes(num_bytes, 'little')


def get_random(num_bytes: int) -> int:
    return bytes_to_long(os.urandom(num_bytes))


def get_random_of_length(num_bytes: int) -> int:
    offset = (num_bytes * 8) - 1
    return get_random(num_bytes) | (1 << offset)


def custom_hash(hash_class: callable, *args: int) -> int:
    hashed = hash_class()
    for i in args:
        if i is not None:
            data = long_to_bytes(i, SRP_LEN_BYTES) if isinstance(i, int) else i
            hashed.update(data)

    return bytes_to_long(hashed.digest())


def delete_duplicates_cookies_and_reset_domain(func):
    def wrapper(self: Self, *args, **kwargs):
        response = func(self, *args, **kwargs)

        current_cookies: dict = self.session.cookies.get_dict()
        new_cookies: dict = response.cookies.get_dict()
        current_cookies.update(new_cookies)  # cookies without duplicates

        self.session.cookies.clear()
        for name, value in current_cookies.items():
            self.session.cookies.set(name=name, value=value)  # reset domain

        return response
    return wrapper
