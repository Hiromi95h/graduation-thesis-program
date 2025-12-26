# agents/decrypt_result.py

from pathlib import Path
from crypto_utils import load_private_key, decrypt_with
import json

BASE = Path(__file__).resolve().parent.parent
KEYS = BASE / "keys"
MSGS = BASE / "messages"


def main():
    a_priv = load_private_key(KEYS / "A_priv.pem")
    in_path = MSGS / "D_to_A.bin"

    if not in_path.exists():
        print("[A] D_to_A.bin がまだ存在しません。")
        return

    cipher = in_path.read_bytes()
    plaintext = decrypt_with(a_priv, cipher)

    result_obj = json.loads(plaintext.decode("utf-8"))
    print("[A] 復号結果:")
    print(json.dumps(result_obj, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()



