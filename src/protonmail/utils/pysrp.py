"""Secure Remote Password(SRP) downloaded from the official repository.
https://github.com/ProtonMail/proton-python-client/blob/master/proton/srp/_pysrp.py

N    A large safe prime (N = 2q+1, where q is prime)
     All arithmetic is done modulo N.
g    A generator modulo N
k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
s    User's salt
I    Username
p    Cleartext Password
H()  One-way hash function
^    (Modular) Exponentiation
u    Random scrambling parameter
a,b  Secret ephemeral values
A,B  Public ephemeral values
x    Private key (derived from p and s)
v    Password verifier
"""
from typing import Union, Optional

from ..constants import SRP_LEN_BYTES, SALT_LEN_BYTES
from .utils import (
    pm_hash,
    bytes_to_long,
    custom_hash,
    get_random_of_length,
    hash_password,
    long_to_bytes,
    generate_srp_salt,
)


def get_ng(modulus_bin: bytes, g_hex: bytes) -> tuple[int, int]:
    return bytes_to_long(modulus_bin), int(g_hex, 16)


def hash_k(hash_class: callable, g: int, modulus: int, width: int) -> int:
    hashed = hash_class()
    hashed.update(g.to_bytes(width, 'little'))
    hashed.update(modulus.to_bytes(width, 'little'))
    return bytes_to_long(hashed.digest())


def password_hasher(hash_class: callable, salt: bytes, password: bytes, modulus: int) -> int:
    # Ensure salt is bytes
    if isinstance(salt, str):
        salt = salt.encode('utf-8')

    hashed_password = hash_password(
        hash_class,
        password,
        salt,
        long_to_bytes(modulus, SRP_LEN_BYTES),
    )
    return bytes_to_long(hashed_password)


def calculate_client_proof(hash_class: callable, challenge_int: int, server_challenge_int: int, session_key: bytes) -> bytes:
    hashed = hash_class()
    hashed.update(long_to_bytes(challenge_int, SRP_LEN_BYTES))
    hashed.update(long_to_bytes(server_challenge_int, SRP_LEN_BYTES))
    hashed.update(session_key)
    return hashed.digest()


def calculate_server_proof(hash_class: callable, challenge_int: int, client_proof: bytes, session_key: bytes) -> bytes:
    hashed = hash_class()
    hashed.update(long_to_bytes(challenge_int, SRP_LEN_BYTES))
    hashed.update(client_proof)
    hashed.update(session_key)
    return hashed.digest()


class User:
    def __init__(self, password: str, modulus_bin: bytes, g_hex: bytes = b"2", srp_version: Optional[int] = None):
        self.password: bin = password.encode()
        self.hash_class = pm_hash
        self.modulus_int, self.g = get_ng(modulus_bin, g_hex)
        self.k = hash_k(self.hash_class, self.g, self.modulus_int, SRP_LEN_BYTES)
        self.srp_version = srp_version # Store SRP version if provided

        self.random_int = get_random_of_length(32)
        self.challenge_int = pow(self.g, self.random_int, self.modulus_int)
        self.expected_server_proof = None
        self._authenticated = False

        self.bytes_s = None
        self.v = None # Stores the verifier as int
        self.bytes_v = None # Stores the verifier as bytes
        self.client_proof = None
        self.session_key = None
        self.S = None
        self.server_challenge_int = None
        self.hashed_server_challenge = None
        self.hashed_password = None # Stores x, the private key (hashed_password)

    def authenticated(self) -> bool:
        return self._authenticated

    def get_challenge(self) -> bytes:
        return long_to_bytes(self.challenge_int, SRP_LEN_BYTES)

    def process_challenge(self, bytes_s: bytes, bytes_server_challenge: bytes) -> Union[bytes, None]:
        """Returns M or None if SRP-6a safety check is violated."""
        self.bytes_s = bytes_s
        self.server_challenge_int = bytes_to_long(bytes_server_challenge)

        # SRP-6a safety check
        if (self.server_challenge_int % self.modulus_int) == 0:
            return None

        self.hashed_server_challenge = custom_hash(
            self.hash_class,
            self.challenge_int,
            self.server_challenge_int
        )

        # SRP-6a safety check
        if self.hashed_server_challenge == 0:
            return None

        self.hashed_password = password_hasher(
            self.hash_class,
            self.bytes_s,
            self.password,
            self.modulus_int
        )
        self.v = pow(self.g, self.hashed_password, self.modulus_int)
        self.S = pow(
            (self.server_challenge_int - self.k * self.v),
            (self.random_int + self.hashed_server_challenge * self.hashed_password),
            self.modulus_int
        )

        self.session_key = long_to_bytes(self.S, SRP_LEN_BYTES)
        self.client_proof = calculate_client_proof(
            self.hash_class,
            self.challenge_int,
            self.server_challenge_int,
            self.session_key
        )
        self.expected_server_proof = calculate_server_proof(
            self.hash_class,
            self.challenge_int,
            self.client_proof,
            self.session_key
        )

        return self.client_proof

    def verify_session(self, server_proof: bytes) -> None:
        if self.expected_server_proof == server_proof:
            self._authenticated = True

    def compute_v(self, bytes_s: Optional[bytes] = None) -> tuple[bytes, bytes]:
        if bytes_s is None:
            self.bytes_s = generate_srp_salt()
        else:
            # Ensure salt is bytes
            if isinstance(bytes_s, str):
                self.bytes_s = bytes_s.encode('utf-8')
            else:
                self.bytes_s = bytes_s

        self.hashed_password = password_hasher( # This is x = H(s, H(I, p))
            self.hash_class,
            self.bytes_s,
            self.password,
            self.modulus_int
        )
        self.v = pow(self.g, self.hashed_password, self.modulus_int)
        self.bytes_v = long_to_bytes(self.v, SRP_LEN_BYTES)

        # Return salt as base64 encoded string and verifier as hex encoded string
        return (
            self.bytes_s.decode('utf-8'), # Salt for AuthVerifier
            self.bytes_v.hex() # Verifier for AuthVerifier
        )

    def get_srp_verifier_params(self, modulus_id: str, salt: Optional[str] = None) -> dict:
        """
        Generates and returns SRP salt and verifier needed for account creation.
        :param modulus_id: The ID of the SRP modulus.
        :param salt: Optional salt. If not provided, a new one will be generated.
        :return: A dictionary containing 'Salt' (str) and 'Verifier' (hex str).
        """
        generated_salt_str, verifier_hex = self.compute_v(bytes_s=salt)
        return {
            "Version": self.srp_version or 4, # Default to 4 if not set during init
            "ModulusID": modulus_id,
            "Salt": generated_salt_str,
            "Verifier": verifier_hex
        }

    def get_ephemeral_secret(self) -> bytes:
        return long_to_bytes(self.random_int, SRP_LEN_BYTES)

    def get_session_key(self) -> Union[bytes, None]:
        return self.session_key if self._authenticated else None
