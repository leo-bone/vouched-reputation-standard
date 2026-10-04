#!/usr/bin/env python3
"""
examples/verify_example.py
==================================================================
任何人拿到 sample-credential.json + issuer.pub，无需任何签发方密钥即可离线验真。

运行：python examples/verify_example.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vprs import verify_credential


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "sample-credential.json")) as f:
        cred = json.load(f)
    with open(os.path.join(here, "issuer.pub")) as f:
        pub = json.load(f)

    res = verify_credential(cred, pub["pubkey"])
    print("issuer_id:", cred.get("issuer_id"))
    print("agent_id :", cred.get("agent_id"))
    print("alg      :", cred.get("alg"))
    print("settlements:", len(cred.get("settlements", [])))
    print("summary  :", cred.get("summary"))
    print("---")
    if res["valid"]:
        print("✅ VALID — 凭证完整、集合未被改、确由该 issuer 私钥签发。")
        print("   可采信该 Agent 的支付验证型声誉，无需信任签发方数据库。")
    else:
        print("❌ INVALID — 问题：")
        for i in res["issues"]:
            print("   -", i)


if __name__ == "__main__":
    main()
