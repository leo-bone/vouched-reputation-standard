# VPRS — Vouched Portable Reputation Standard

> **让 AI Agent 的声誉可携带、可独立验真。** 一份开放标准 + 零依赖参考实现：声誉由"已结算的托管交易"派生，并用签发方私钥签名；任何第三方无需信任签发方数据库，只要用签发方公开的公钥即可采信。

这是 AI 劳务市场的"信任层标准"——目标是成为可验证 AI 工作的通用语言，就像 HTTPS 之于 Web。

## 为什么需要它

- 平台内评分离开平台就归零、无法被别处采信；
- 自报声誉没有代价，可随意刷高；
- 链上身份（mint）≠ 干过活、干得好。

VPRS 的不可伪造性来自两点：**声誉绑定真实资金行为**（伪造好声誉 = 真金白银跑托管），以及**非对称签名**（签发方私钥签名、公钥公开验真）。

## 30 秒体验

```bash
# 1) 生成一份演示凭证 + 演示签发方密钥（DEMO 密钥，仅用于说明）
python examples/gen_example.py

# 2) 任何人拿凭证 + 公钥，无需签发方密钥即可离线验真
python examples/verify_example.py
```

输出 `✅ VALID` 即表示：凭证完整、集合未被改、确由该签发方私钥签发，可采信其中的支付验证型声誉。

## 在你的项目里用

```python
from vprs import build_credential, verify_credential

# 签发方（持有私钥）
cred = build_credential(agent_id="ag_x", issuer_id="you.example.com",
                        settlements=[...], summary={...}, priv_hex=PRIV,
                        alg="secp256k1", key_id="2026")

# 第三方（仅有公钥）
res = verify_credential(cred, PUB_HEX)
if res["valid"]:
    ...  # 采信该 Agent 的声誉
```

命令行：

```bash
python -m vprs issue  --priv <64hex> --issuer you.example.com --agent ag_x \
       --settlements settlements.json --out cred.json
python -m vprs verify --cred cred.json --pub issuer.pub
```

## 规范

完整规范性定义见 **[SPEC.md](SPEC.md)**：数据结构、密码学构造（`proof_hash` / `root_hash` / `issuer_sig`）、验证算法、跨平台导入、版本兼容与安全说明。

要点速览：
- `proof_hash`：结算事实的**无密钥**承诺（sha256，任何人可重算检测篡改）。
- `root_hash`：全部 `proof_hash` 的聚合根。
- `issuer_sig`：签发方对 `(root_hash | agent_id | issuer_id | issued_at | key_id)` 的签名，支持 `secp256k1`（默认，纯标准库、零依赖）与 `ed25519`（可选，需 `cryptography`）。
- 公钥通过 `https://{issuer_id}/.well-known/vprs-pubkey.json` 公开。

## 依赖

- **核心（secp256k1）零三方依赖**，仅用 Python 标准库。
- `ed25519` 路径可选，需 `pip install cryptography`（见 `requirements.txt`）。

## 测试

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

含：secp256k1 已知向量、签发→验真往返、篡改检测（proof/root/sig）、跨实现一致性、导入去重、ed25519（可选）。

## 与 Vouched 的关系

Vouched（[leo-bone/vouched](https://github.com/leo-bone/vouched)，私有仓）是该标准的**首个合规签发方**：其线上凭证端点输出 VPRS 兼容结构，并通过 `/api/reputation/pubkey` 与 `/.well-known/vprs-pubkey.json` 公开验签公钥。本标准仓库独立于产品，欢迎任何平台实现并采用。

## 已登记签发方（Issuer Registry）

标准不只是规范，还要有**可被独立验真的真实签发方**。登记册见 [`issuers/`](issuers/)，目前收录：

- **[`vouched.uichain.org`](issuers/vouched.json)** —— Vouched，首个合规签发方 / 参考实现。

任何人都能照着登记册里的 `well_known_url` 实时取公钥，再对 Vouched 产出的 `vprs/v1` 凭证调用 `vprs.verify_credential(cred, pub)` 验真，**无需信任 Vouched 的数据库**。

> 当前合规证据：跨实现一致性测试已证明——用本仓库 `vprs` 参考库验证 Vouched 产品代码产出的凭证，`valid=True`；篡改 `proof_hash` 或 `issuer_sig` 均被双方实现拒绝。Vouched 的公开演示站点将在完成 VPS 迁移后 24/7 提供实时验签端点（详见登记册的 `deployment_status`）。

想让你的平台也登记进来？看 [`issuers/README.md`](issuers/README.md) 的三步流程——这就是 VPRS「让 AI 声誉跨平台可携带」落地的路径。

## 许可

MIT。标准文本与参考实现均可自由实现、采用、fork、商业化。
