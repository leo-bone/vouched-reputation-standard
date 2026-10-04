#!/usr/bin/env python3
"""
examples/gen_example.py
==================================================================
生成一份 VPRS 演示凭证 + 演示签发方密钥（DEMO，仅用于说明，切勿用于生产）。

运行：python examples/gen_example.py
产出：
  examples/issuer.key         演示私钥（DEMO / INSECURE）
  examples/issuer.pub         演示公钥（非压缩 hex）+ 派生地址
  examples/sample-credential.json  一份可被任何人离线验真的凭证
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vprs import build_credential, _secp256k1 as k1

# ⚠️ DEMO ONLY —— 固定私钥仅为让示例可复现；生产必须用随机且离线保管的密钥。
DEMO_PRIV_HEX = "0x" + "2b" * 32  # 纯演示，非真实密钥


def derive_pub(priv_hex):
    priv = int(priv_hex, 16)
    x, y = k1.priv_to_pub(priv)
    pub = "0x04" + x.to_bytes(32, "big").hex() + y.to_bytes(32, "big").hex()
    addr = k1.pub_to_address((x, y))
    return pub, addr


def demo_summary(settlements):
    settled = [s for s in settlements if s["outcome"] == "settled"]
    failed = [s for s in settlements if s["outcome"] == "failed"]
    total = len(settled) + len(failed)
    sr = (len(settled) / total) if total else 0.0
    earned = round(sum(s["amount_usd"] for s in settled), 2)
    rated = [s["rating"] for s in settled if s["rating"] > 0]
    avg = round(sum(rated) / len(rated), 2) if rated else 0.0
    rep = round(5.0 * (0.6 * sr + 0.4 * (avg / 5.0)), 2) if total else None
    return {
        "settled_count": len(settled),
        "failed_count": len(failed),
        "total_earned_usd": earned,
        "avg_rating": avg,
        "success_rate": round(sr, 3),
        "reputation": rep,
        "score": None,
        "tier": "reliable",
        "tier_label": "可靠",
        "portable": False,
    }


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    priv = DEMO_PRIV_HEX
    pub, addr = derive_pub(priv)

    settlements = [
        {"id": "st_1", "task_id": "task_alpha", "agent_id": "ag_demo",
         "origin_agent_id": "ag_demo", "issuer_id": "vouched.uichain.org",
         "amount_usd": 80.00, "category": "data", "outcome": "settled",
         "rating": 5.0, "ts": 1690000000},
        {"id": "st_2", "task_id": "task_beta", "agent_id": "ag_demo",
         "origin_agent_id": "ag_demo", "issuer_id": "vouched.uichain.org",
         "amount_usd": 120.00, "category": "data", "outcome": "settled",
         "rating": 4.0, "ts": 1690000500},
        {"id": "st_3", "task_id": "task_gamma", "agent_id": "ag_demo",
         "origin_agent_id": "ag_demo", "issuer_id": "vouched.uichain.org",
         "amount_usd": 50.00, "category": "code", "outcome": "failed",
         "rating": 0.0, "ts": 1690001000},
    ]

    cred = build_credential(
        agent_id="ag_demo",
        issuer_id="vouched.uichain.org",
        settlements=settlements,
        summary=demo_summary(settlements),
        priv_hex=priv,
        alg="secp256k1",
        key_id="vouched-2026",
    )

    with open(os.path.join(here, "issuer.key"), "w") as f:
        f.write(priv + "\n")
    with open(os.path.join(here, "issuer.pub"), "w") as f:
        json.dump({"issuer_id": "vouched.uichain.org", "key_id": "vouched-2026",
                   "alg": "secp256k1", "pubkey": pub, "address": addr}, f, indent=2)
    with open(os.path.join(here, "sample-credential.json"), "w") as f:
        json.dump(cred, f, indent=2, ensure_ascii=False)

    print("issuer address:", addr)
    print("pubkey:", pub[:20], "...")
    print("credential root_hash:", cred["root_hash"])
    print("wrote issuer.key / issuer.pub / sample-credential.json")
    print("verify with: python examples/verify_example.py")


if __name__ == "__main__":
    main()
