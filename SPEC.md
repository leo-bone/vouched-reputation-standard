# VPRS — Vouched Portable Reputation Standard

**版本：v1（schema 标识 `vprs/v1`）**
**状态：公开标准（开源实现见本仓库）**
**作者：Vouched**
**许可：标准文本与参考实现均以 MIT 许可发布，可自由实现、采用、fork。**

---

## 0. 一句话定义

> **VPRS 是一份"可独立验真"的 AI Agent 工作声誉回执标准：声誉由"已结算的托管交易"派生，并用签发方私钥签名；任何第三方无需信任签发方数据库，只要用签发方公布的公钥即可采信。**

它是 AI 劳务市场的"信任层标准"——类比 HTTPS 之于 Web：不是某个平台的私有评分，而是跨平台可携带、可验证的声誉凭证。

---

## 1. 为什么需要这个标准（问题与动机）

| 现有做法 | 问题 |
|---|---|
| 平台内"评分/星级" | 离开平台即归零；无法被其他平台采信 |
| 自报声誉 / 自卖自夸 | 没有代价，可随意刷高 |
| 链上身份（如 ERC-8004 式 mint） | 身份 ≠ 声誉；铸造了不等于干过活、干得好 |
| 共享密钥 / HMAC 签名 | 验证方必须持有签发方密钥 → 无法"无需信任"地验真 |

**VPRS 的不可伪造性来自两点：**
1. **声誉绑定真实资金行为**：只有"跑过真实托管结算"的 Agent 才有结算记录，伪造一笔好声誉 = 真金白银跑一笔托管，成本极高。
2. **非对称签名**：签发方持私钥签名，公钥公开；第三方用公钥验真，无需任何签发方密钥。

---

## 2. 核心概念

- **Issuer（签发方）**：产生结算、签发凭证的平台（如 Vouched）。每个 issuer 有唯一 `issuer_id`（推荐用其域名，如 `vouched.uichain.org`）和一对非对称密钥。公钥通过 issuer 的 `.well-known/vprs-pubkey.json` 或等价端点公开。
- **Settlement（结算 / 原子证据）**：一次托管结算（放款 `settled` 或拒付 `failed`）的事实记录，是声誉的最小不可篡改单元。
- **Credential（凭证）**：一个 Agent 在某 issuer 的全部 Settlement 的签名聚合包，即可携带声誉载体。
- **key_id**：签发方轮换密钥时用于区分不同公钥版本的标识。

---

## 3. 数据结构

### 3.1 Settlement（结算回执）

```json
{
  "id": "st_8f3a...",
  "task_id": "task_1",
  "agent_id": "ag_abc",
  "origin_agent_id": "ag_abc",
  "issuer_id": "vouched.uichain.org",
  "amount_usd": 80.00,
  "category": "data",
  "outcome": "settled",
  "rating": 5.0,
  "ts": 1690000000,
  "proof_hash": "0x9f2c..."
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | 结算唯一标识（issuer 内唯一） |
| `task_id` | string | 关联任务 |
| `agent_id` | string | 该笔结算归属的 Agent（在导入方命名空间内的 id） |
| `origin_agent_id` | string | 结算原发平台的 Agent 身份；跨平台导入时保留，使结算归属清晰、可去重 |
| `issuer_id` | string | 签发方标识（推荐域名） |
| `amount_usd` | number | 结算金额（USD，2 位小数） |
| `category` | string | 工作品类（垂直市场可复用） |
| `outcome` | enum | `settled` \| `failed` |
| `rating` | number | 1–5（failed 记为 0） |
| `ts` | integer | Unix 秒 |
| `proof_hash` | string | 见 3.3 |

### 3.2 Credential（可携带凭证）

```json
{
  "schema": "vprs/v1",
  "agent_id": "ag_abc",
  "issuer_id": "vouched.uichain.org",
  "issued_at": 1690000123,
  "key_id": "vouched-2026",
  "alg": "secp256k1",
  "settlements": [ "<Settlement>..." ],
  "summary": {
    "settled_count": 12,
    "failed_count": 1,
    "total_earned_usd": 980.00,
    "avg_rating": 4.6,
    "success_rate": 0.923,
    "reputation": 4.6,
    "score": 78.5,
    "tier": "reliable",
    "tier_label": "可靠",
    "portable": true
  },
  "root_hash": "0x3b1d...",
  "issuer_sig": "0x..."
}
```

`summary` 是签发方对 Settlement 集合的派生画像（**完全由 Settlement 列表计算，不单独可信**）；第三方应以其自己的 `summary` 计算为准，本字段仅作便捷展示。

---

## 4. 密码学构造（规范性）

### 4.1 `proof_hash`（承诺回执）

纯承诺，**不含任何密钥**，任何人都能重算以检测篡改：

```
canonical(s) = join("|", [
    s.origin_agent_id,
    s.task_id,
    s.issuer_id,
    fmt2(s.amount_usd),     # 固定 2 位小数
    s.category,
    s.outcome,
    fmt2(s.rating),         # 固定 2 位小数
    fmt0(s.ts)              # 整数秒
])
proof_hash  = "0x" + sha256(canonical(s))[0:40]   # 前 40 hex
```

> 设计理由：不含密钥，第三方即可独立重算并比对，实现"无需信任"的 tamper-evidence。真正的签发权威来自 4.3 的签名。

### 4.2 `root_hash`（聚合根）

```
root_hash = "0x" + sha256(concat(proof_hash for each settlement in canonical order))[0:48]
```

`canonical order` = 按 `ts` 升序（或等于 build 时的排序）。任何对结算集合的增删改都会改变 `root_hash`。

### 4.3 `issuer_sig`（签发方签名）与 `alg`

签名覆盖的规范化字符串与摘要：

```
signed_string = join("|", [ root_hash, agent_id, issuer_id, fmt0(issued_at), key_id ])
digest       = sha256(signed_string)              # 32 字节
issuer_sig   = sign(alg, issuer_private_key, digest)
```

支持的 `alg`：

| alg | 曲线/方案 | 密钥 | 实现 | 用途 |
|---|---|---|---|---|
| `secp256k1` | secp256k1 ECDSA（低 s 规范化） | 32 字节私钥 / 非压缩 65 字节公钥（`0x04+x+y`） | **纯标准库**（本仓库 `_secp256k1.py`，零依赖） | 默认；与链上出金同源，便于把声誉与支付锚定到同一链上身份 |
| `ed25519` | Ed25519 | 32 字节私钥 / 32 字节公钥 | `cryptography`（可选依赖） | 更轻量，适合纯离线/移动端验证 |

**`issuer_sig` 编码**：`"0x" + 十六进制`。
- secp256k1：`r`(32 字节) ‖ `s`(32 字节) 拼接的 64 字节十六进制。
- ed25519：64 字节签名的十六进制。

---

## 5. 验证算法（第三方，无需签发方密钥）

```
function verify(cred, issuer_pubkey):
    issues = []
    for each settlement in cred.settlements:
        if proof_hash(settlement) != settlement.proof_hash:
            issues += "settlement tampered"
    if root_hash(cred.settlements) != cred.root_hash:
        issues += "settlement set altered"
    digest = sha256(signed_string(cred))
    if not verify(alg, issuer_pubkey, digest, cred.issuer_sig):
        issues += "issuer_sig invalid"
    return (issues == [], issues)
```

当且仅当三步全过，`valid = true`：凭证完整、集合未被改、确由该 issuer 私钥签发。此时可采信其中的支付验证型声誉。**验证方应使用自己从 Settlement 重算的 `summary`，而非盲目信任凭证里的 `summary`。**

issuer 公钥获取：访问 `https://{issuer_id}/.well-known/vprs-pubkey.json`，返回：

```json
{ "issuer_id": "vouched.uichain.org", "key_id": "vouched-2026",
  "alg": "secp256k1", "pubkey": "0x04...." }
```

---

## 6. 可携带性 / 跨平台导入

1. 导入方对凭证调用 `verify(cred, issuer_pubkey)`，必须 `valid`。
2. 逐条 Settlement 以 `imported = true` 导入，**按 `(issuer_id, proof_hash)` 去重**，避免同一笔结算重复计入。
3. `origin_agent_id` 保留，使结算仍归因原发平台身份；导入方据此计算"该 Agent 的可携带口碑"。
4. 一个 Agent 可聚合来自多个 issuer 的凭证，形成跨平台统一声誉。

---

## 7. 版本与兼容性

- `schema` 字段标识大版本（`vprs/v1`）。算法演进通过 `alg` + `key_id` 表达，不破坏旧凭证验证。
- 旧版 HMAC/共享密钥式凭证（如 `vouched.reputation.credential/v1`）**不在本标准范围内**——它们要求验证方持密钥，不满足"无需信任"前提。迁移到 VPRS 即把 `platform_sig` 换成 4.3 的非对称 `issuer_sig`，并把 `proof_hash` 改为无密钥承诺。

---

## 8. 实现清单（互操作性最低要求）

一个"VPRS 兼容"的签发方/验证方至少应：
- 支持 `proof_hash` / `root_hash` 的 4.1 / 4.2 构造（逐字节一致）。
- 至少支持 `secp256k1` 一种 `alg` 的签名与验签。
- 公开可获取的公钥端点（`.well-known/vprs-pubkey.json` 或等价）。
- 在凭证中包含 3.2 的全部必填字段。

---

## 9. 安全说明

- `proof_hash` 不含密钥 → 任何人可重算检测篡改；但**伪造一个通过验证的凭证需要签发方私钥**，而非仅知道算法。
- 私钥必须离线/受控保管；轮换时发新 `key_id` 并保留旧公钥一段时间以便旧凭证仍可验真。
- 本标准是"声誉信任锚"，不转移资金；但签发方若同时做链上支付，建议复用同一 secp256k1 密钥以把声誉与支付锚定到同一链上身份（并严格隔离热钱包出金权限，见 Vouched 项目的安全实践）。
- 参考实现 `_secp256k1.py` 的任何改动都必须先过 `tests/test_vprs.py` 的签名/验签向量。
