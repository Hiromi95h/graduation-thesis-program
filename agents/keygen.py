# crypto/keygen.py

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
KEYS = BASE / "keys"
KEYS.mkdir(exist_ok=True)


def generate(name):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    with open(KEYS / f"{name}_priv.pem", "wb") as f:
        f.write(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    with open(KEYS / f"{name}_pub.pem", "wb") as f:
        f.write(
            pub.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def main():
    for name in ["A", "B", "C"]:
        generate(name)
    print("鍵生成完了")


if __name__ == "__main__":
    main()


