# agents/User.py

import json
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
MSGS = BASE / "messages"
CONFIG_PATH = MSGS / "user_config.json"


def prompt_int(label, default, min_value, max_value):
    while True:
        raw = input(f"{label} [{default}]: ").strip()
        if raw == "":
            return default
        try:
            value = int(raw)
        except ValueError:
            print("数値を入力してください。")
            continue
        if value < min_value or value > max_value:
            print(f"{min_value}〜{max_value}の範囲で入力してください。")
            continue
        return value


def prompt_choice(label, default, choices):
    choices_str = ", ".join(choices)
    while True:
        raw = input(f"{label} [{default}] ({choices_str}): ").strip()
        if raw == "":
            return default
        if raw in choices:
            return raw
        print(f"選択肢から入力してください: {choices_str}")


def main():
    print("=== エージェント登録 ===")
    registered_agents = {
        "AgentA": prompt_choice("AgentA を登録しますか", "y", ["y", "n"]) == "y",
        "AgentB": prompt_choice("AgentB を登録しますか", "y", ["y", "n"]) == "y",
        "AgentC": prompt_choice("AgentC を登録しますか", "y", ["y", "n"]) == "y",
    }

    print("\n=== エージェントレベル設定 ===")
    agent_levels = {
        "AgentA": prompt_int("AgentA レベル (0-3)", 1, 0, 3),
        "AgentB": prompt_int("AgentB レベル (0-3)", 2, 0, 3),
        "AgentC": prompt_int("AgentC レベル (0-3)", 2, 0, 3),
    }

    print("\n=== データレベル設定 ===")
    data_levels = {
        "data_level1.txt": prompt_int("data_level1.txt レベル (1-3)", 1, 1, 3),
        "data_level2.txt": prompt_int("data_level2.txt レベル (1-3)", 2, 1, 3),
        "data_level3.txt": prompt_int("data_level3.txt レベル (1-3)", 3, 1, 3),
    }

    print("\n=== タスク設定 ===")
    situation_level = prompt_int("situation_level (1 or 2)", 1, 1, 2)
    data_id = prompt_choice("取得したいデータID", "data_level2.txt", list(data_levels.keys()))

    config = {
        "registered_agents": registered_agents,
        "agent_levels": agent_levels,
        "data_levels": data_levels,
        "task": {
            "situation_level": situation_level,
            "data_id": data_id,
        },
    }

    MSGS.mkdir(exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False))
    print("\n設定を保存しました。")


if __name__ == "__main__":
    main()
