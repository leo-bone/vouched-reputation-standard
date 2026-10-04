"""
tests/test_vprs.py — VPRS 参考实现测试

覆盖：
  - secp256k1 签发→验真 往返
  - 篡改检测（proof_hash / root_hash / issuer_sig）
  - 跨实现一致性（独立按 SPEC 公式重算 proof_hash / root_hash）
  - 导入去重
  - ed25519 路径（仅当 cryptography 可用时）
  - _secp256k1 已知向量（priv=1 → 生成元 G）
"""
import json
import os
import random
import secrets
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from vprs import build_credential, verify_credential, import_decisions
from vprs import commitment as C
from vprs import _secp256k1 as k1


def rand_priv():
    return secrets.token_hex(32)


def make_settlements(n=5, issuer="issuer.example.com"):
    out = []
    for i in range(n):
        out.append({
            "id": f"st_{i}",
            "task_id": f"task_{i}",
            "agent_id": "ag_x",
            "origin_agent_id": "ag_x",
            "issuer_id": issuer,
            "amount_usd": round(random.uniform(10, 200), 2),
            "category": "data" if i % 2 else "code",
            "outcome": "settled" if i != n - 1 else "failed",
            "rating": 5.0 if i != n - 1 else 0.0,
            "ts": 1690000000 + i * 100,
        })
    return out


def make_summary():
    return {"settled_count": 4, "failed_count": 1, "total_earned_usd": 500.0,
            "avg_rating": 5.0, "success_rate": 0.8, "reputation": 4.8,
            "score": 70.0, "tier": "reliable", "tier_label": "可靠",
            "portable": False}


class TestSecp256k1Vectors(unittest.TestCase):
    def test_priv1_is_generator(self):
        x, y = k1.priv_to_pub(1)
        self.assertEqual((x, y), k1.G)

    def test_sign_verify_roundtrip(self):
        priv = rand_priv()
        pub = "0x04" + k1.priv_to_pub(int(priv, 16))[0].to_bytes(32, "big").hex() + \
              k1.priv_to_pub(int(priv, 16))[1].to_bytes(32, "big").hex()
        digest = k1.sha256(b"hello vprs")
        r, s, _v = k1.sign_digest(int(priv, 16), digest)
        self.assertTrue(k1.verify_digest(k1.priv_to_pub(int(priv, 16)), digest, r, s))


class TestCredential(unittest.TestCase):
    def setUp(self):
        self.priv = rand_priv()
        self.pub = "0x04" + k1.priv_to_pub(int(self.priv, 16))[0].to_bytes(32, "big").hex() + \
                   k1.priv_to_pub(int(self.priv, 16))[1].to_bytes(32, "big").hex()
        self.sett = make_settlements()
        self.cred = build_credential("ag_x", "issuer.example.com", self.sett,
                                     make_summary(), self.priv, alg="secp256k1",
                                     key_id="k1")

    def test_roundtrip_valid(self):
        res = verify_credential(self.cred, self.pub)
        self.assertTrue(res["valid"], res["issues"])

    def test_tamper_proof_hash_detected(self):
        c = json.loads(json.dumps(self.cred))
        c["settlements"][0]["rating"] = 1.0
        res = verify_credential(c, self.pub)
        self.assertFalse(res["valid"])
        self.assertTrue(any("proof_hash" in i for i in res["issues"]))

    def test_tamper_root_detected(self):
        c = json.loads(json.dumps(self.cred))
        c["settlements"].append(json.loads(json.dumps(c["settlements"][0])))
        c["settlements"][-1]["id"] = "st_injected"
        res = verify_credential(c, self.pub)
        self.assertFalse(res["valid"])
        self.assertTrue(any("root_hash" in i for i in res["issues"]))

    def test_bad_signature_detected(self):
        c = json.loads(json.dumps(self.cred))
        c["issuer_sig"] = "0x" + "00" * 64
        res = verify_credential(c, self.pub)
        self.assertFalse(res["valid"])
        self.assertTrue(any("issuer_sig" in i for i in res["issues"]))


class TestCrossImplConsistency(unittest.TestCase):
    """独立按 SPEC 公式重算，确保参考实现与规范逐字节一致。"""

    def test_proof_hash_formula(self):
        s = make_settlements(1)[0]
        # 参考实现
        got = C.proof_hash(s)
        # 独立重算
        payload = "|".join([
            str(s["origin_agent_id"]), str(s["task_id"]), str(s["issuer_id"]),
            f"{float(s['amount_usd']):.2f}", str(s["category"]),
            str(s["outcome"]), f"{float(s['rating']):.2f}", f"{int(float(s['ts']))}",
        ])
        import hashlib
        exp = "0x" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]
        self.assertEqual(got, exp)
        self.assertTrue(got.startswith("0x"))
        self.assertEqual(len(got), 42)

    def test_root_hash_formula(self):
        sett = make_settlements(3)
        cred = build_credential("ag_x", "i", sett, make_summary(),
                               rand_priv(), alg="secp256k1", key_id="k")
        import hashlib
        joined = "".join(s["proof_hash"] for s in cred["settlements"])
        exp = "0x" + hashlib.sha256(joined.encode("utf-8")).hexdigest()[:48]
        self.assertEqual(cred["root_hash"], exp)

    def test_signed_digest_covers_identity(self):
        cred = build_credential("ag_x", "i", make_settlements(),
                               make_summary(), rand_priv(), alg="secp256k1", key_id="k")
        import hashlib
        sstr = "|".join([cred["root_hash"], cred["agent_id"], cred["issuer_id"],
                         f"{int(float(cred['issued_at']))}", cred["key_id"]])
        exp = hashlib.sha256(sstr.encode("utf-8")).digest()
        self.assertEqual(C.signed_digest(cred), exp)


class TestImportDedup(unittest.TestCase):
    def setUp(self):
        self.priv = rand_priv()
        self.pub = "0x04" + k1.priv_to_pub(int(self.priv, 16))[0].to_bytes(32, "big").hex() + \
                   k1.priv_to_pub(int(self.priv, 16))[1].to_bytes(32, "big").hex()
        self.cred = build_credential("ag_x", "issuer.example.com", make_settlements(),
                                     make_summary(), self.priv, alg="secp256k1", key_id="k")

    def test_import_then_reimport_skips(self):
        existing = set()
        r1 = import_decisions(self.cred, existing)
        self.assertEqual(r1["imported"], len(self.cred["settlements"]))
        self.assertEqual(r1["skipped"], 0)
        r2 = import_decisions(self.cred, existing)
        self.assertEqual(r2["imported"], 0)
        self.assertEqual(r2["skipped"], len(self.cred["settlements"]))

    def test_dedup_by_issuer_and_proof(self):
        existing = {("issuer.example.com", self.cred["settlements"][0]["proof_hash"])}
        r = import_decisions(self.cred, existing)
        self.assertEqual(r["imported"], len(self.cred["settlements"]) - 1)


class TestEd25519Optional(unittest.TestCase):
    def test_ed25519_if_available(self):
        try:
            import cryptography  # noqa
        except Exception:
            self.skipTest("cryptography not installed (ed25519 path optional)")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key().public_bytes_raw().hex()
        cred = build_credential("ag_x", "i", make_settlements(), make_summary(),
                               priv.private_bytes_raw().hex(), alg="ed25519", key_id="k")
        res = verify_credential(cred, pub)
        self.assertTrue(res["valid"], res["issues"])


class TestIssuerRegistry(unittest.TestCase):
    """登记册里的快照公钥必须与参考演示密钥一致，否则会误导接入方。"""

    def test_vouched_registry_matches_demo_key(self):
        with open(os.path.join(ROOT, "issuers", "vouched.json")) as f:
            reg = json.load(f)
        with open(os.path.join(ROOT, "examples", "issuer.pub")) as f:
            demo = json.load(f)
        self.assertEqual(reg["pubkey"], demo["pubkey"],
                         "issuers/vouched.json 的 pubkey 必须与 examples/issuer.pub（演示密钥）一致")
        self.assertEqual(reg["alg"], "secp256k1")
        self.assertEqual(reg["key_id"], "vouched-2026")
        self.assertTrue(reg["well_known_url"].endswith("/.well-known/vprs-pubkey.json"))


if __name__ == "__main__":
    unittest.main()
