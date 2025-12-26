# crypto/crypto_utils.py
import json
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from keygen import generate as generate_rsa_keypair


def generate_aes_key():
    return os.urandom(32)  # AES-256


# ========= RSA LOAD =========
def _maybe_generate_keypair(path):
    path = Path(path)
    stem = path.stem
    if stem.endswith("_priv"):
        name = stem[:-5]
        priv_path = path
        pub_path = path.with_name(f"{name}_pub.pem")
    elif stem.endswith("_pub"):
        name = stem[:-4]
        pub_path = path
        priv_path = path.with_name(f"{name}_priv.pem")
    else:
        return False

    if priv_path.exists() or pub_path.exists():
        return False

    generate_rsa_keypair(name)
    return True


def load_private_key(path):
    path = Path(path)
    if not path.exists():
        _maybe_generate_keypair(path)
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path):
    path = Path(path)
    if not path.exists():
        _maybe_generate_keypair(path)
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# ========= RSA Encryption =========
def rsa_encrypt(pubkey, data: bytes) -> str:
    ciphertext = pubkey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(privkey, data_b64: str) -> bytes:
    ciphertext = base64.b64decode(data_b64)
    return privkey.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# ========= AES-GCM =========
def aes_encrypt(key: bytes, plaintext: bytes):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def aes_decrypt(key: bytes, enc: dict):
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(enc["nonce"])
    ciphertext = base64.b64decode(enc["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)


# ========= Envelope Signature =========

def canonical_bytes(env):
    return json.dumps(env, sort_keys=True, separators=(",", ":")).encode()


def sign_envelope(priv, env):
    message = canonical_bytes(env)
    signature = priv.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def verify_envelope(pub, env, sig_b64):
    try:
        pub.verify(
            base64.b64decode(sig_b64),
            canonical_bytes(env),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


