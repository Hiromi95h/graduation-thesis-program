# agents/agent_B.py

import json
import time
import hashlib
from pathlib import Path
from crypto_utils import (
    load_public_key, load_private_key,
    verify_envelope, sign_envelope,
    rsa_decrypt, aes_encrypt
)
from agent_registry import provide_shared_key

BASE = Path(__file__).resolve().parent.parent
MSGS = BASE / "messages"
KEYS = BASE / "keys"


def main():
    # 1. A→B を受信
    env = json.loads((MSGS / "A_to_B.json").read_text())
    a_pub = load_public_key(KEYS / "A_pub.pem")

    sigA = env["signatures"][0]["sig"]
    env_no_sig = dict(env)
    env_no_sig.pop("signatures", None)
    if not verify_envelope(a_pub, env_no_sig, sigA):
        raise RuntimeError("[B] User の署名検証失敗！")

    print("[B] User 署名 OK")
    print("[B] A→B の連携が成功しました。")

    # 2. Registry に共通鍵を要求
    if not provide_shared_key("AgentB", "AgentC"):
        print("[B] 連携を中断しました。Registryに登録してください。")
        return

    # 3. Registry→B を受信し復号
    reg_msg = json.loads((MSGS / "registry_to_B.json").read_text())
    enc_key = reg_msg["key_for_B"]

    b_priv = load_private_key(KEYS / "B_priv.pem")
    shared_key = rsa_decrypt(b_priv, enc_key)

    print("[B] 共通鍵を復号しました。")
    print("[B] Registry との連携が成功しました。")

    # 4. C 用の envelope を作る
    new_env = {
        "task": env["task"],
        "meta": {
            "delegation_chain": env["meta"]["delegation_chain"],
        }
    }

    prev_hash = "GENESIS"
    if new_env["meta"]["delegation_chain"]:
        prev_hash = new_env["meta"]["delegation_chain"][-1].get("hash", "GENESIS")

    delegation_entry = {"from": "B", "to": "C", "timestamp": time.time(), "prev_hash": prev_hash}
    payload = {
        "from": delegation_entry["from"],
        "to": delegation_entry["to"],
        "timestamp": delegation_entry["timestamp"],
        "prev_hash": delegation_entry["prev_hash"],
    }
    delegation_entry["hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    new_env["meta"]["delegation_chain"].append(delegation_entry)

    sigB = sign_envelope(b_priv, new_env)
    new_env["signatures"] = [{"by": "AgentB", "sig": sigB}]

    # 5. AES 暗号化して送信
    encrypted = aes_encrypt(shared_key, json.dumps(new_env).encode())

    (MSGS / "B_to_C.enc").write_text(json.dumps(encrypted, indent=2))
    print("[B] タスクを AES で暗号化し AgentC へ送信しました。")
    print("[B] B→C の連携が成功しました。")


if __name__ == "__main__":
    main()
