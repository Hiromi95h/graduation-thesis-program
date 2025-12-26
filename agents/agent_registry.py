# agents/agent_registry.py

import json
import secrets
import hashlib
import time
from pathlib import Path
from crypto_utils import (
    generate_aes_key, rsa_encrypt, load_public_key
)
from typing import Optional


BASE = Path(__file__).resolve().parent.parent
KEYS = BASE / "keys"
MSGS = BASE / "messages"
DATA_DIR = BASE / "data"
TOKENS_FILE = MSGS / "registry_tokens.json"
USER_CONFIG = MSGS / "user_config.json"


# 連携可否マトリクス
ALLOW_MATRIX = {
    ("AgentB", "AgentC"): True,
    ("AgentB", "AgentD"): False,
}

def can_link(src, dst):
    return ALLOW_MATRIX.get((src, dst), False)


def load_user_config():
    if not USER_CONFIG.exists():
        raise FileNotFoundError(f"User config not found: {USER_CONFIG}")
    data = json.loads(USER_CONFIG.read_text())
    return (
        data.get("agent_levels", {}),
        data.get("data_levels", {}),
        data.get("registered_agents", {}),
    )


def get_agent_levels():
    user_levels, _, _ = load_user_config()
    if not user_levels:
        raise ValueError("agent_levels missing in user config")
    return dict(user_levels)


def get_data_catalog():
    _, data_levels, _ = load_user_config()
    if not data_levels:
        raise ValueError("data_levels missing in user config")
    return {name: {"level": lvl, "path": DATA_DIR / name} for name, lvl in data_levels.items()}


def get_registered_agents():
    _, _, registered = load_user_config()
    return registered


def is_registered(name: str) -> bool:
    registered = get_registered_agents()
    return registered.get(normalize_agent_name(name), False)


def normalize_agent_name(name: str) -> str:
    if name.startswith("Agent"):
        return name
    if len(name) == 1 and name.isalpha():
        return f"Agent{name.upper()}"
    return name


def get_agent_level(name: str) -> int:
    agent_levels = get_agent_levels()
    return agent_levels.get(normalize_agent_name(name), 0)


def collect_history_levels(delegation_chain):
    levels = []
    for item in delegation_chain or []:
        from_agent = item.get("from")
        to_agent = item.get("to")
        if from_agent:
            levels.append(get_agent_level(from_agent))
        if to_agent:
            levels.append(get_agent_level(to_agent))
    return levels


def get_history_min_level(delegation_chain):
    levels = collect_history_levels(delegation_chain)
    return min(levels) if levels else None


def collect_delegator_levels(delegation_chain):
    levels = []
    for item in delegation_chain or []:
        from_agent = item.get("from")
        if from_agent:
            levels.append(get_agent_level(from_agent))
    return levels


def get_delegator_min_level(delegation_chain):
    levels = collect_delegator_levels(delegation_chain)
    return min(levels) if levels else None


def get_immediate_delegator_level(delegation_chain):
    if not delegation_chain:
        return None
    from_agent = delegation_chain[-1].get("from")
    if not from_agent:
        return None
    return get_agent_level(from_agent)


def evaluate_access(
    data_level,
    agent_level,
    situation_level,
    delegator_min_level,
    immediate_delegator_level,
):
    def raw_share_with_delegator():
        return delegator_min_level is not None and delegator_min_level >= data_level

    def raw_share_with_delegatee():
        return False

    def delegatee_rule(level_required):
        return {
            "delegatee_min_level": level_required,
            "delegatee_rule": f"level>={level_required}",
        }

    if situation_level == 2:
        allowed = data_level >= 1
        return allowed, {
            "mode": "emergency_unrestricted",
            "with_delegator": allowed,
            **delegatee_rule(0),
            "raw_with_delegator": allowed and raw_share_with_delegator(),
            "raw_with_delegatee": False,
        }

    if situation_level != 1:
        raise ValueError(f"Unknown situation_level: {situation_level}")

    if data_level == 0:
        allowed = False
        return allowed, {
            "mode": "level0_blocked",
            "with_delegator": False,
            "delegatee_min_level": None,
            "delegatee_rule": "blocked",
            "raw_with_delegator": False,
            "raw_with_delegatee": False,
        }

    if data_level == 1:
        allowed = agent_level >= 1
        return allowed, {
            "mode": "level1_unrestricted",
            "with_delegator": allowed,
            **delegatee_rule(0),
            "raw_with_delegator": allowed and raw_share_with_delegator(),
            "raw_with_delegatee": False,
        }

    if data_level == 2:
        allowed = agent_level >= 2
        return allowed, {
            "mode": "level2_conditional",
            "with_delegator": allowed and (immediate_delegator_level or 0) >= 2,
            **delegatee_rule(2),
            "raw_with_delegator": allowed and raw_share_with_delegator(),
            "raw_with_delegatee": False,
        }

    if data_level == 3:
        allowed = agent_level >= 3 and (immediate_delegator_level or 0) >= 1
        return allowed, {
            "mode": "level3_conditional",
            "with_delegator": allowed and (immediate_delegator_level or 0) >= 3,
            **delegatee_rule(3),
            "raw_with_delegator": allowed and raw_share_with_delegator(),
            "raw_with_delegatee": False,
        }

    raise ValueError(f"Unknown data_level: {data_level}")


def _canonical_hash_payload(entry, prev_hash):
    payload = {
        "from": entry.get("from"),
        "to": entry.get("to"),
        "timestamp": entry.get("timestamp"),
        "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def verify_delegation_chain(delegation_chain):
    if not delegation_chain:
        return True

    prev_hash = "GENESIS"
    for entry in delegation_chain:
        entry_hash = entry.get("hash")
        entry_prev = entry.get("prev_hash")
        if not entry_hash or entry_prev != prev_hash:
            return False

        expected = hashlib.sha256(_canonical_hash_payload(entry, prev_hash)).hexdigest()
        if entry_hash != expected:
            return False

        prev_hash = entry_hash

    return True


def provide_shared_key(src: str, dst: str):
    """
    B→C 連携が許可されているか確認し、
    共通鍵を生成し両者の公開鍵で暗号化して配布
    """
    if not is_registered(src) or not is_registered(dst):
        print(f"[Registry] 未登録エージェント: {src} または {dst}")
        return False
    if not can_link(src, dst):
        raise RuntimeError(f"[Registry] 連携禁止: {src} → {dst}")

    shared_key = generate_aes_key()

    src_pub = load_public_key(KEYS / f"{src[-1]}_pub.pem")
    dst_pub = load_public_key(KEYS / f"{dst[-1]}_pub.pem")

    enc_for_src = rsa_encrypt(src_pub, shared_key)
    enc_for_dst = rsa_encrypt(dst_pub, shared_key)

    # 出力（BとCが読み取る）
    (MSGS / "registry_to_B.json").write_text(
        json.dumps({"key_for_B": enc_for_src}, indent=2)
    )

    (MSGS / "registry_to_C.json").write_text(
        json.dumps({"key_for_C": enc_for_dst}, indent=2)
    )

    print("[Registry] 共通鍵を生成し B と C に配布しました。")
    return True


def load_tokens():
    if not TOKENS_FILE.exists():
        return {}
    return json.loads(TOKENS_FILE.read_text())


def save_tokens(tokens):
    TOKENS_FILE.write_text(json.dumps(tokens, indent=2, ensure_ascii=False))


def issue_data_token(requesting_agent: str, data_id: str, situation_level: int,
                     delegation_chain, next_agent: Optional[str] = None):
    """
    データアクセス可否と共有ポリシーを判定し、許可ならトークンを発行
    """
    req_agent = normalize_agent_name(requesting_agent)
    if not is_registered(req_agent):
        print(f"[Registry] 未登録エージェント: {req_agent}")
        return False
    data_catalog = get_data_catalog()
    entry = data_catalog.get(data_id)
    if not entry:
        print(f"[Registry] 未登録データ: {data_id}")
        return False

    agent_level = get_agent_level(req_agent)
    history_min_level = get_history_min_level(delegation_chain)
    delegator_min_level = get_delegator_min_level(delegation_chain)
    immediate_delegator_level = get_immediate_delegator_level(delegation_chain)
    chain_ok = verify_delegation_chain(delegation_chain)
    allowed, share_policy = evaluate_access(
        entry["level"],
        agent_level,
        situation_level,
        delegator_min_level,
        immediate_delegator_level,
    )

    result = {
        "requester": req_agent,
        "data_id": data_id,
        "data_level": entry["level"],
        "situation_level": situation_level,
        "agent_level": agent_level,
        "history_min_level": history_min_level,
        "delegator_min_level": delegator_min_level,
        "immediate_delegator_level": immediate_delegator_level,
        "share_policy": share_policy,
        "access_granted": allowed,
        "delegation_chain_valid": chain_ok,
    }

    if allowed and chain_ok:
        token = secrets.token_urlsafe(16)
        tokens = load_tokens()
        tokens[token] = {
            "requester": req_agent,
            "data_id": data_id,
            "issued_at": time.time(),
            "situation_level": situation_level,
            "share_policy": share_policy,
        }
        save_tokens(tokens)
        result["token"] = token
        result["message"] = "Access token issued."
    else:
        if not chain_ok:
            result["reason"] = "Delegation chain invalid"
        else:
            result["reason"] = "Access denied by policy"
        result["message"] = "Access token not issued."

    out_name = f"registry_token_to_{req_agent[-1]}.json"
    (MSGS / out_name).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    if allowed:
        print("[Registry] アクセストークンを発行しました。")
    else:
        print("[Registry] アクセストークンは発行されませんでした。")
    return allowed


def fetch_data_with_token(requesting_agent: str, token: str):
    """
    発行済みトークンを検証し、データを返す
    """
    req_agent = normalize_agent_name(requesting_agent)
    tokens = load_tokens()
    entry = tokens.get(token)

    result = {
        "requester": req_agent,
        "token_valid": False,
    }

    if not entry:
        result["reason"] = "Token not found"
        result["message"] = "Token validation failed."
    elif entry["requester"] != req_agent:
        result["reason"] = "Token requester mismatch"
        result["message"] = "Token validation failed."
    else:
        data_catalog = get_data_catalog()
        data_entry = data_catalog.get(entry["data_id"])
        if not data_entry:
            result["reason"] = "Data not registered"
            result["message"] = "Token validation failed."
        else:
            result["token_valid"] = True
            result["data_id"] = entry["data_id"]
            result["data"] = data_entry["path"].read_text()
            result["share_policy"] = entry.get("share_policy")
            result["message"] = "Data access granted."
            entry["last_used_at"] = time.time()
            tokens[token] = entry
            save_tokens(tokens)

    out_name = f"data_to_{req_agent[-1]}.json"
    (MSGS / out_name).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"[Registry] データ応答を {out_name} に出力しました。")
    if result["token_valid"]:
        print("[Registry] トークン検証成功。データアクセスを許可しました。")
        print("[Registry] データ利用ポリシー:")
        print(json.dumps(result.get("share_policy"), ensure_ascii=False, indent=2))
    else:
        print("[Registry] トークン検証失敗。データアクセスを拒否しました。")
