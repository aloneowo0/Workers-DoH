# Workers-DoH

基于 Cloudflare Workers 的轻量级 DNS over HTTPS 代理，支持 8 上游并发竞速、自动 EDNS Client-Subnet 注入。

## 快速开始

1. Fork 本仓库
2. 编辑 `.env`：启用需要的上游，调整参数
3. 运行 `npm run build`（调用 `scripts/build-config.cjs`）生成 `config.js`
4. 部署到 Cloudflare Workers（连接仓库自动部署，或 `npx wrangler deploy`）

之后修改 `.env` 重新构建推送即可自动更新。

## 端点参考

所有端点支持 `POST application/dns-message`（wire format）和 `GET ?name=&type=`。设置 `Accept: application/dns-json` 时走 RFC 8484 JSON 透传（直连 Google DNS）。

| 端点 | 说明 |
|------|------|
| `/` | 首页（中文） |
| `/en` | 首页（英文） |
| `/health` | JSON 健康检查 |
| `/dns-query` | 全部已启用上游并发竞速（mix） |
| `/<provider>/dns-query` | 单上游查询 |

provider 可选值（依 `.env` 启用情况而定）：`google` `cloudflare_Public` `quad9` `adguard` `opendns` `dnspod` `alidns` `nextdns` 及自定义 `CUSTOM_*`。

支持 DNS 类型：A（默认）、AAAA、HTTPS(65)、SVCB(64)、TXT、MX、CNAME、NS、SOA、PTR。

```bash
# GET 查询（mix 模式）
curl "https://your-worker.dev/dns-query?name=example.com&type=AAAA"

# 单上游查询
curl "https://your-worker.dev/google/dns-query?name=example.com&type=A"

# POST wire-format
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin \
  "https://your-worker.dev/dns-query"

# ?dns=base64 参数
curl "https://your-worker.dev/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# JSON 健康检查
curl "https://your-worker.dev/health"
```

### 查询参数

| 参数 | 类型 | 说明 |
|------|------|------|
| `name` | string | 查询域名（与 `type` 搭配） |
| `type` | string | DNS 记录类型，默认 A |
| `dns` | string | Base64 编码的 DNS wire format 请求（与 `name` 互斥） |

## EDNS 处理（全局自动）

所有查询走统一 EDNS 处理流程，无需手动指定模式：

1. **ECS 注入**：若请求不含 ECS 选项，从 `CF-Connecting-IP` 提取客户端 IP，注入 `/24`（IPv4）或 `/56`（IPv6）子网
2. **UDP 4096**：确保 OPT 记录的 UDP 负载大小设为 4096
3. **DO 位**：设置 DNSSEC OK 位，请求 DNSSEC 记录
4. **黑名单过滤**：应答中的 A/AAAA 记录命中 `BLOCKED_CIDRS` 时整包丢弃

ECS 依赖 `CF-Connecting-IP` 请求头，仅在 Cloudflare 代理环境下可用。

## 竞速算法（concurrentAll）

mix 端点的核心逻辑，8 个上游并发竞速：

```
t=0          并发发送所有上游
             ├── 保护窗 (ECS_PROTECT_MS) ─────────┤
t=~10ms      [ECS 上游] 到 → 有效 → 立即返回
t=~15ms      [非 ECS 上游] 到 → 有效 → 入暂存区（不返回）
             ...
t=ECS_PROTECT_MS
             保护窗到期
             ├── 暂存区有非 ECS 响应 → 释放最快的一条
             └── 暂存区空 → 进入自由竞速
             ...
t=自由竞速    任意有效响应（ECS 或非 ECS）立即返回
             ...
t=HARD_TIMEOUT_MS
             硬超时
             ├── 暂存区有响应 → 释放最快的一条
             └── 全部无效 → SERVFAIL(code=22)
```

- **ECS_PROTECT_MS**（默认 20ms）：保护窗口。窗口内只接受支持 ECS 的上游的响应，非 ECS 响应暂存。窗口到期释放最快暂存，之后所有上游平等竞速。
- **HARD_TIMEOUT_MS**（默认 800ms）：总超时。超时后不再等待。

## 上游列表

| 上游 | ECS | URL |
|------|-----|-----|
| google | ✅ | dns.google/dns-query |
| cloudflare_Public | ❌ | cloudflare-dns.com/dns-query |
| quad9 | ✅ | dns11.quad9.net/dns-query |
| adguard | ✅ | dns.adguard-dns.com/dns-query |
| opendns | ✅ | dns.opendns.com/dns-query |
| dnspod | ✅ | sm2.doh.pub（国内） |
| alidns | ✅ | dns.alidns.com（国内） |
| nextdns | ✅ | dns.nextdns.io |

## 配置

编辑 `.env`，运行 `npm run build` 生成 `config.js`。

```env
# 预设上游开关
GOOGLE=true
CLOUDFLARE_PUBLIC=true
QUAD9=true
ADGUARD=true
OPENDNS=true
YANDEX=false
DNSPOD=true
ALIDNS=true
360=false
NEXTDNS=true

# 自定义上游（格式：CUSTOM_<名称>=<DoH URL>）
# CUSTOM_MY=https://my-doh.example.com/dns-query

# 竞速参数（毫秒）
HARD_TIMEOUT_MS=800
ECS_PROTECT_MS=20

# ECS 子网前缀
ECS_PREFIX4=24
ECS_PREFIX6=56

# 应答 IP 黑名单（CIDR 空格分隔）
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128
```

`CUSTOM_` 上游默认标记 `ecs: true`，名称仅限字母数字和下划线。

## 应答过滤

`BLOCKED_CIDRS` 定义 IPv4/IPv6 黑名单 CIDR。上游返回的 A/AAAA 记录命中任意范围时整包丢弃，返回 SERVFAIL（含 EDE code）。默认拦截：127.0.0.0/8、0.0.0.0/32、::/128、::1/128。

## 首页

访问 `/`（中文）或 `/en`（英文）可查看内置管理页，包含：
- 所有可用端点的路径列表
- 各上游 ECS 支持情况表
- 在线延迟检测工具（选择端点 → 开始测试，显示总延迟和上游处理时间 X-Upstream-Time）

## 响应头

| 头 | 说明 |
|----|------|
| `X-Upstream-Time` | 上游处理耗时（ms），仅 DNS 查询响应包含 |

## 项目结构

```
Workers-DoH/
├── .env                      # 用户配置：上游开关、超时、前缀等
├── scripts/build-config.cjs  # 构建脚本：解析 .env 生成 config.js
├── config.js                 # 运行时配置（自动生成）
├── _worker.js                # Worker 入口：路由分发、并发竞速
├── router.js                 # URL 路由解析
├── edns.js                   # DNS 包解析、EDNS 注入/过滤
├── homepage.js               # 中英文首页（ECS 表、延迟检测）
├── wrangler.jsonc            # Cloudflare 部署配置
└── package.json
```

## 注意事项

- **mix 端点保证可用**：单上游可能因网络波动或策略限制返回错误，mix 并发竞速可覆盖这些缺陷。生产使用建议始终走 `/dns-query`。
- **CF 并发上限**：Workers 免费计划约 6 个并发 subrequest，标准付费约 8-10 个。mix 模式超配额的上游会内部排队，建议启用不超过 8 个上游。
- **CF-Connecting-IP**：ECS 注入依赖此请求头，仅在 Cloudflare 代理环境下可用。非 CF 环境需自行传入客户端 IP。
- **cloudflare_Public 无 ECS**：该上游不支持 EDNS Client-Subnet，主要用于测试保护窗口的暂存释放机制。
- **自定义上游默认值**：`CUSTOM_*` 默认 `ecs: true`。若上游不支持，需在 `build-config.cjs` 的预设表中调整。
- **Yandex / 360**：默认关闭，延迟较高或兼容性不佳，按需启用。
