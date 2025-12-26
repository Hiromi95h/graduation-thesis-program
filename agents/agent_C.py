# agents/agent_C.py

import json
from pathlib import Path
from crypto_utils import (
    load_private_key, load_public_key,
    rsa_decrypt, aes_decrypt, verify_envelope
)
from agent_registry import issue_data_token, fetch_data_with_token

BASE = Path(__file__).resolve().parent.parent
MSGS = BASE / "messages"
KEYS = BASE / "keys"


def main():
    # 1. Registry → C の共通鍵（暗号化）を受信
    msg = json.loads((MSGS / "registry_to_C.json").read_text())
    enc_key = msg["key_for_C"]

    c_priv = load_private_key(KEYS / "C_priv.pem")
    shared_key = rsa_decrypt(c_priv, enc_key)

    print("[C] 共通鍵を復号しました。")

    # 2. B からの暗号化メッセージを受信
    encrypted = json.loads((MSGS / "B_to_C.enc").read_text())
    decrypted_bytes = aes_decrypt(shared_key, encrypted)

    env = json.loads(decrypted_bytes.decode())

    # 3. B の署名検証
    b_pub = load_public_key(KEYS / "B_pub.pem")
    sigB = env["signatures"][0]["sig"]
    env_no_sig = dict(env)
    env_no_sig.pop("signatures", None)

    if not verify_envelope(b_pub, env_no_sig, sigB):
        raise RuntimeError("[C] B の署名検証失敗！→ なりすまし攻撃の可能性")

    print("[C] B の署名 OK")
    print("[C] B→C の連携が成功しました。")

    # 4. タスク実行
    task = env["task"]
    print("[C] タスク実行を実行しました。")

    # 5. データアクセス要求（Registry 判定）
    data_req = task.get("data_request")
    if data_req and "data_id" in data_req:
        situation_level = task.get("situation_level", 1)
        if not issue_data_token(
            "AgentC",
            data_req["data_id"],
            situation_level,
            env["meta"].get("delegation_chain", []),
        ):
            print("[C] 連携を中断しました。Registryに登録してください。")
            return

        result = json.loads((MSGS / "registry_token_to_C.json").read_text())
        if result["access_granted"]:
            print("[C] データアクセス許可:", result["data_id"])
            print("[C] 共有ポリシー:")
            print(json.dumps(result["share_policy"], ensure_ascii=False, indent=2))
            token = result["token"]
            fetch_data_with_token("AgentC", token)

            data_result = json.loads((MSGS / "data_to_C.json").read_text())
            if data_result.get("token_valid"):
                print("[C] データ内容:", data_result["data"])
                print("[C] データ取得に成功しました。")
            else:
                print("[C] トークン無効:", data_result.get("reason"))
                print("[C] データ取得に失敗しました。")
        else:
            print("[C] データアクセス拒否:", result.get("reason"))
            print("[C] データ取得に失敗しました。")


if __name__ == "__main__":
    main()
