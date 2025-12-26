# agents/agent_A.py

import json
import time
import hashlib
from pathlib import Path
from crypto_utils import load_private_key, sign_envelope

BASE = Path(__file__).resolve().parent.parent
MSGS = BASE / "messages"
KEYS = BASE / "keys"
USER_CONFIG = MSGS / "user_config.json"


def load_task_config():
    if not USER_CONFIG.exists():
        return {}
    data = json.loads(USER_CONFIG.read_text())
    return data.get("task", {})


def main():
    priv = load_private_key(KEYS / "A_priv.pem")

    task_config = load_task_config()
    situation_level = int(task_config.get("situation_level", 1))
    data_id = task_config.get("data_id", "data_level2.txt")
    created_at = time.time()

    env = {
        "task": {
            "task_id": "task1",
            "action": "fetch_data",
            "payload": {"url": "https://example.com"},
            "situation_level": situation_level,
            "data_request": {"data_id": data_id},
        },
        "meta": {
            "created_at": created_at,
            "delegation_chain": [],
        },
    }

    delegation_entry = {
        "from": "A",
        "to": "B",
        "timestamp": created_at,
        "prev_hash": "GENESIS",
    }
    payload = {
        "from": delegation_entry["from"],
        "to": delegation_entry["to"],
        "timestamp": delegation_entry["timestamp"],
        "prev_hash": delegation_entry["prev_hash"],
    }
    delegation_entry["hash"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    env["meta"]["delegation_chain"].append(delegation_entry)

    sig = sign_envelope(priv, env)
    env["signatures"] = [{"by": "User", "sig": sig}]

    (MSGS / "A_to_B.json").write_text(json.dumps(env, indent=2))
    print("[A] タスクを AgentB に送りました。")


if __name__ == "__main__":
    main()
