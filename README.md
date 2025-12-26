# エージェント連携・データアクセス制御の概要

このコードは、エージェント間の委任（delegation）とデータ共有に対して
署名検証・委任履歴・レベル判定に基づくアクセス制御を行う仕組みを可視化したものです。

## 主な構成

- `agents/agent_A.py`  
  タスクを作成し、A→B の委任履歴（delegation_chain）を作って署名付きで送信します。
- `agents/agent_B.py`  
  A の署名を検証し、Registry から共通鍵を受け取って B→C に暗号化して中継します。
- `agents/agent_C.py`  
  B の署名を検証し、Registry にデータアクセスの可否を問い合わせます。
- `agents/agent_registry.py`  
  連携可否、委任履歴の検証、データアクセスの判定、共有ポリシーの発行を担当します。

## 委任履歴（delegation_chain）

委任履歴は `meta.delegation_chain` に追加され、  
A→B→C のように全ての委任元・委任先が記録されます。

## アクセス判定の考え方（概要）

- 状況レベルに応じてアクセス許可条件が変わります。
- データレベルに応じてアクセス可否が決まります。
- 生データ共有は **委任先への共有は禁止**。
- 生データ共有は **多段階委任で全ての委任元レベルがデータレベル以上** の場合のみ許可。
- 加工データの委任先共有は「委任先レベルが何以上なら可」という形で出力します。

## 共有ポリシーの出力例

```json
{
  "mode": "level2_conditional",
  "with_delegator": true,
  "delegatee_min_level": 2,
  "delegatee_rule": "level>=2",
  "raw_with_delegator": true,
  "raw_with_delegatee": false
}
```

- `with_delegator`: 加工データを委任元へ共有可能か
- `delegatee_min_level`: 加工データを委任先へ共有可能となる最小レベル
- `raw_with_delegator`: 生データを委任元へ共有可能か
- `raw_with_delegatee`: 生データを委任先へ共有可能か（常に `false`）
