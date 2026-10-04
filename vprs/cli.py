#!/usr/bin/env python3
"""
vprs/cli.py — VPRS 命令行工具（签发 / 验真）。

签发示例：
  python -m vprs issue --priv <64hex> --issuer vouched.uichain.org \
        --agent ag_demo --settlements examples/settlements.json --out cred.json

验真实例：
  python -m vprs verify --cred cred.json --pub examples/issuer.pub

公钥文件可以是 issuer.pub（含 pubkey 字段的 JSON）或纯 hex 文本。
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vprs import build_credential, verify_credential


def _load_pub(pub_arg: str) -> str:
    if os.path.exists(pub_arg):
        with open(pub_arg) as f:
            data = json.load(f)
        return data.get("pubkey") or data.get("pub")
    return pub_arg.strip()


def cmd_issue(args):
    with open(args.settlements) as f:
        settlements = json.load(f)
    priv = args.priv.strip()
    cred = build_credential(
        agent_id=args.agent,
        issuer_id=args.issuer,
        settlements=settlements,
        summary=args.summary or {},
        priv_hex=priv,
        alg=args.alg,
        key_id=args.key_id,
    )
    with open(args.out, "w") as f:
        json.dump(cred, f, indent=2, ensure_ascii=False)
    print("issued ->", args.out)
    print("root_hash:", cred["root_hash"])
    print("issuer_sig:", cred["issuer_sig"][:24], "...")


def cmd_verify(args):
    with open(args.cred) as f:
        cred = json.load(f)
    pub = _load_pub(args.pub)
    res = verify_credential(cred, pub)
    if res["valid"]:
        print("VALID — 凭证可信，可采信支付验证型声誉。")
    else:
        print("INVALID:")
        for i in res["issues"]:
            print("  -", i)
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="VPRS — Vouched Portable Reputation Standard CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("issue", help="签发一份 VPRS 凭证")
    pi.add_argument("--priv", required=True, help="签发方私钥（64 hex，secp256k1；ed25519 视 alg）")
    pi.add_argument("--issuer", required=True, help="issuer_id（推荐域名）")
    pi.add_argument("--agent", required=True, help="agent_id")
    pi.add_argument("--settlements", required=True, help="结算列表 JSON 文件")
    pi.add_argument("--out", required=True, help="输出凭证 JSON 路径")
    pi.add_argument("--alg", default="secp256k1")
    pi.add_argument("--key-id", default=None)
    pi.add_argument("--summary", default=None, help="可选 summary JSON 文件（否则留空 {}）")
    pi.set_defaults(func=cmd_issue)

    pv = sub.add_parser("verify", help="验真一份 VPRS 凭证")
    pv.add_argument("--cred", required=True, help="凭证 JSON 文件")
    pv.add_argument("--pub", required=True, help="公钥：issuer.pub 路径或纯 hex")
    pv.set_defaults(func=cmd_verify)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
