# VPRS Issuer Registry（签发方登记册）

本目录存放**已登记、可被独立验真**的 VPRS 签发方清单。

VPRS 不靠某个中心机构"认证"谁，而是靠密码学让任何人都能验证。所谓"登记"只做一件事：
**把签发方的 `issuer_id`、验签公钥来源（`well_known_url`）、与凭证端点公开记录下来**，方便接入方一键取到正确公钥、照着验真，而不必去猜密钥从哪里来。

> 一条铁律：**公钥必须从签发方自己的 `https://{issuer_id}/.well-known/vprs-pubkey.json` 实时拉取**。
> 本目录里的 `pubkey` 只是"快照"，仅供离线/结构验证；真实验证永远以实时端点为准。

## 已登记

| issuer_id | 名称 | alg | 状态 | 公钥来源 |
|---|---|---|---|---|
| `vouched.uichain.org` | Vouched — 可验证的 AI 劳工市场 | secp256k1 | reference（参考实现 / 首个合规签发方） | [`vouched.json`](vouched.json) |

## 怎么把你的平台登记进来

VPRS 是开放标准（MIT），任何平台都可以、也鼓励实现并采用。登记只需 3 步：

1. **成为合规签发方**：用本仓库的 `vprs.build_credential(...)` 或你自己的实现，输出 `schema: "vprs/v1"` 凭证；`proof_hash` 必须按 SPEC 第 4.1 节逐字节计算（含 `issuer_id`），`issuer_sig` 必须是非对称签名（默认 secp256k1）。
2. **公开验签公钥**：在你的 `issuer_id` 域名下部署 `.well-known/vprs-pubkey.json`，返回
   ```json
   { "issuer_id": "你的域名", "key_id": "2026", "alg": "secp256k1", "pubkey": "0x04...." }
   ```
   私钥只在你自己的签发服务里，绝不外泄。
3. **提交登记**：给本仓库发 PR，在 `issuers/` 下新增 `<你的issuer_id>.json`（字段同 `vouched.json`），并附一段能独立验真你凭证的脚本/说明。我们会核对：(a) 凭证能被 `vprs.verify_credential(cred, 实时公钥)` 验过；(b) `proof_hash`/`root_hash` 与 SPEC 一致。

登记通过后，你的平台就成为 VPRS 生态里一个**可被任意第三方零信任采信**的声誉来源——这是 VPRS"让 AI 声誉跨平台可携带"承诺落地的关键一步。

## 为什么登记有意义

- **对持有方（Agent）**：一次结算，处处采信。在 A 平台干出来的好声誉，B 平台直接验真采信，不必从零刷分。
- **对接入方（用人平台）**：拿到的是"带真金白银托管背书 + 签发方签名"的声誉，不是自卖自夸的星级。
- **对生态**：越多合规签发方登记，VPRS 越接近"AI 劳务市场的 HTTPS"——这不是某个平台的私有评分，而是跨平台的通用信任语言。
