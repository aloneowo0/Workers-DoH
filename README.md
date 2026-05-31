# Workers-DoH v2 — Cloudflare Workers DNS-over-HTTPS 代理

基于 Cloudflare Workers 的 DoH 代理，支持 8 个上游并发竞速、EDNS 客户端子网注入、ECH 加密 ClientHello 注入（Cloudflare / Meta CDN）、CDN 归属检测、Twitter/X 域名重映射、IP 黑名单过滤。

## 架构

```
                         ┌──────────────────┐
                         │    _worker.js     │
                         │  入口 / 路由 / 调度 │
                         └──┬───┬───┬───┬──┘
                            │   │   │   │
          ┌─────────────────┘   │   │   └──────────────┐
          ▼                     │   │                  ▼
   ┌────────────┐              │   │           ┌──────────────┐
   │   mix.js   │              │   │           │  homepage.js │
   │ 多上游竞速  │              │   │           │  中英文首页   │
   │ ECS 保护窗 │              │   │           └──────────────┘
   └─────┬──────┘              │   │
         │                     │   │
         ▼                     │   │
   ┌────────────┐              │   │
   │  edns.js   │              │   │
   │ ECS 注入   │              │   │
   │ IP 黑名单  │              │   │
   └─────┬──────┘              │   │
         │                     │   │
         ▼                     ▼   ▼
   ┌──────────────────────────────────────┐
   │              dns-lib.js              │
   │  DNS 线格式 / 响应构建 / 内部解析      │
   └─────┬──────────────────┬─────────────┘
         │                  │
         ▼                  ▼
   ┌──────────┐     ┌────────────────┐
   │  ech.js  │     │special-domain.js│
   │ECH 获取  │     │ 域名重映射      │
   │ECH 注入  │     │ CDN 归属检测    │
   └──────────┘     └────────────────┘
         │                  │
         └────┬─────────────┘
              ▼
       ┌──────────┐
       │config.js │
       │ 运行配置  │
       └──────────┘
```

## 模块说明

| 模块 | 文件 | 职责 | 导出 |
|------|------|------|------|
| 入口 | `_worker.js` | 路由分发 + 总调度：特殊域名预处理、上游分发、JSON 透传 | 默认导出 `fetch` 处理器 |
| 竞速 | `mix.js` | 多上游并发竞速：ECS 保护窗策略 + 赛后 ECH/CF-IP 后处理 | `concurrentAll()` |
| EDNS | `edns.js` | DNS 包解析 + ECS 客户端子网注入 + UDP 4096/DO 位 + IP 黑名单过滤 | `prepareQuery()`, `filterAnswers()` |
| ECH | `ech.js` | CF ECH 配置获取（内部 DNS）+ HTTPS/SVCB RR 解析注入 `ech=`/`alpn=` | `fetchCFEch()`, `injectECH()`, `META_ECH_B64` |
| 特殊域名 | `special-domain.js` | Twitter/X 域名 IP 重映射 + CDN 归属检测（CF/Meta CIDR）+ Meta 域名匹配 | `remapResponse()`, `resolvePreferredIPs()`, `detectOwner()`, `probeOwner()`, `isMetaDomain()`, `extractIps()` |
| DNS 库 | `dns-lib.js` | DNS 线格式编解码、响应构建、SERVFAIL、内部 DNS 解析（竞速 + Google 直连兜底） | `buildDNS()`, `servfail()`, `dnsResponse()`, `resolveDNSWire()`, `resolveDNSWireGoogle()` 等 |
| 首页 | `homepage.js` | 中英文管理首页 + 延迟检测工具 | `serveHomepage()`, `serveHomepageEn()` |
| 配置 | `config.js` | 运行时配置：上游 URL/ECS 标记、超时、ECS 前缀、IP 黑名单、区域优化 | `UPSTREAMS`, `ECS_PROTECT_MS`, `HARD_TIMEOUT_MS`, `REGION_CONFIG` 等 |

## 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 中文首页 |
| `/en` | GET | 英文首页 |
| `/health` | GET | JSON 健康检查 |
| `/dns-query` | GET/POST | 多上游并发竞速（mix） |
| `/:provider/dns-query` | GET/POST | 单上游查询 |

可用上游：`google`、`cloudflare_Public`、`quad9`、`adguard`、`opendns`、`dnspod`、`alidns`、`nextdns`，以及自定义 `CUSTOM_*`。

支持 DNS 类型：A（默认）、AAAA、HTTPS(65)、SVCB(64)、TXT、MX、CNAME、NS、SOA、PTR。

请求格式支持三种：
- `POST application/dns-message` — 二进制线格式
- `GET ?name=xxx&type=A` — URL 参数
- `GET ?dns=<base64>` — Firefox/Chrome DoH 格式
- `Accept: application/dns-json` — RFC 8484 JSON 透传

```bash
# GET 查询（mix 模式）
curl "https://h-demo.mk01.top/dns-query?name=example.com&type=AAAA"

# 单上游
curl "https://h-demo.mk01.top/google/dns-query?name=example.com&type=A"

# POST 线格式
curl -X POST -H "Content-Type: application/dns-message" \
  --data-binary @query.bin "https://h-demo.mk01.top/dns-query"

# Firefox DoH 格式
curl "https://h-demo.mk01.top/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"

# 健康检查
curl "https://h-demo.mk01.top/health"
```

## 功能

### 多上游竞速（mix.js）

`concurrentAll()` 将查询同时发给所有启用的上游，分两个阶段：

```
t=0                    全部上游并发发出
     ┌────────── ECS 保护窗（ECS_PROTECT_MS=20ms）──────────┐
t≈10ms  [ECS 上游] 到达且有效 → 立即返回
t≈15ms  [非 ECS 上游] 到达且有效 → 放入暂存区
     ...
t=20ms  保护窗结束
        暂存区有结果 → 释放最快那条
        暂存区空 → 进入自由竞速
     ...
t=20-800ms  自由竞速
        任意有效响应立即返回
     ...
t=800ms  硬超时
        暂存区有结果 → 释放最快那条
        全部失败 → SERVFAIL（EDE code=22, "No reachable upstream"）
```

**赛后处理**：取得最快响应后，`postProcessBody()` 执行 ECH 注入（HTTPS 类型 + 区域启用）和 CF IP 替换（检测到 Cloudflare edge IP 则替换为区域优选域名解析结果）。

### EDNS / ECS 注入（edns.js）

所有查询经过 `prepareQuery()`：

1. **ECS 注入**：从 `CF-Connecting-IP` 提取客户端 IP，注入 `/24`（IPv4）或 `/56`（IPv6）子网
2. **UDP 4096**：强制 OPT 记录的 UDP 载荷大小为 4096
3. **DO 位**：设置 DNSSEC OK 位
4. **IP 过滤**：`filterAnswers()` 检查响应中所有 A/AAAA 记录是否命中 `BLOCKED_RANGES`，命中则整包丢弃

### ECH 注入（ech.js）

区域启用 ECH（`.env` 中 `REGION_XX_ECH=true`）时生效：

1. **Cloudflare 域名**：通过内部 DNS 解析 `cloudflare-ech.com` 获取 HTTPS RR，提取 `ech=` 和 `alpn=` SvcParam，缓存 10 分钟
2. **Meta CDN 域名**：使用硬编码的 `META_ECH_B64`（来自 TLS retry-config，详见 `META_ECH_HANDOFF.md`）
3. **注入逻辑**：解析上游 DNS 响应，找到 HTTPS/SVCB 应答记录，替换其中 `ech=`/`alpn=` 参数，按 SvcParam key 排序后返回

### CDN 归属检测（special-domain.js）

模块加载时编译两组 CIDR 列表：
- **Cloudflare**：22 个 IPv4 范围 + 7 个 IPv6 范围
- **Meta**：57 个 IPv4 范围 + 20 个 IPv6 范围

`detectOwner(ip)` 同步检测 IP 归属，`probeOwner(domain)` 异步解析域名的 A 记录后逐 IP 检测，缓存 1 小时。

### 域名重映射（special-domain.js）

区域激活时，拦截配置的 remap 域名（如 `twimg.com`、`twitter.com`、`x.com`、`t.co`）：
- **AAAA**：返回空（禁用 IPv6）
- **HTTPS**：注入 CF ECH
- **A**：解析区域优选域名（如 `cf.090227.xyz`）获取 IP，以原域名返回

### Meta 域名 Google 兜底（_worker.js + dns-lib.js）

Meta 域名（`facebook.com`、`instagram.com`、`fbcdn.net` 等）A/AAAA 查询先走 `resolveDNSWire` 竞速全上游。若失败（国内 DNS 对 Meta 域名返回空/污染），自动切换到 `resolveDNSWireGoogle()` 直连 `dns.google/dns-query`，确保国内也能解析。

### IP 黑名单（edns.js + config.js）

`BLOCKED_RANGES` 定义要过滤的 CIDR 范围。命中的 A/AAAA 记录导致整包丢弃。默认拦截：`127.0.0.0/8`、`0.0.0.0/32`、`::/128`、`::1/128`。

## 配置

编辑 `.env`，执行 `npm run build` 生成 `config.js`。

```env
# 上游开关（true = 启用 / false = 禁用）
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

# IP 黑名单（空格分隔 CIDR）
BLOCKED_CIDRS=127.0.0.0/8 0.0.0.0/32 ::/128 ::1/128

# 区域优化
REGION=CN
REGION_CN_PREFERRED=cf.090227.xyz
REGION_CN_REMAP=twimg.com twitter.com x.com t.co
REGION_CN_ECH=true
```

`REGION_XX_*` 按国家代码自动发现，每个区域支持三个参数：
- `REGION_XX_PREFERRED` — 优选域名（CF edge IP 替换目标）
- `REGION_XX_REMAP` — 要拦截的域名（空格分隔）
- `REGION_XX_ECH` — 是否启用 ECH 注入（`true`/`false`）

## 响应头

| 头 | 说明 |
|----|------|
| `Content-Type` | `application/dns-message`（DNS 响应）或 `application/json`（错误/健康） |
| `X-Upstream-Time` | 上游处理耗时（毫秒），仅 DNS 响应附带 |

## 部署

```bash
cd cloudflare-doh-v2

# 1. 编辑 .env
# 2. 生成 config.js
npm run build

# 3. 部署到 Cloudflare Workers
npm run deploy

# 或本地开发
npm run dev
```

## 项目结构

```
cloudflare-doh-v2/
├── .env                      # 用户配置（编辑此文件）
├── scripts/
│   └── build-config.cjs      # 构建脚本：解析 .env → 生成 config.js
├── config.js                 # 运行时配置（自动生成，勿手动编辑）
├── _worker.js                # 入口：路由、调度、特殊域名预处理
├── mix.js                    # 多上游竞速引擎 + 赛后处理
├── edns.js                   # DNS 包解析、ECS 注入、IP 过滤
├── ech.js                    # ECH 配置获取 + HTTPS/SVCB RR 注入
├── special-domain.js         # 域名重映射、CDN 归属检测、CIDR 匹配
├── dns-lib.js                # DNS 线格式 / 响应构建 / 内部解析 统一库
├── homepage.js               # 中英文管理首页 + 延迟检测工具
├── META_ECH_HANDOFF.md       # Meta CDN ECH retry-config 获取文档
├── wrangler.jsonc            # Cloudflare Workers 部署配置
├── package.json
└── README.md
```

## 注意事项

- **推荐使用 mix 端点**：单上游可能因网络不稳定或策略限制失败，`/dns-query`（mix）并发竞速能兜底
- **CF 子请求限制**：免费计划约 6 并发，付费约 8-10。建议启用不超过 8 个上游
- **CF-Connecting-IP**：ECS 注入依赖此头，仅 Cloudflare 代理下可用
- **ECSI 保护窗**：`cloudflare_Public` 不支持 ECS，在保护窗内会被暂存而非立即返回——这是设计行为，用于测试保护窗机制
- **ECH 区域控制**：ECH 注入仅当 `REGION_XX_ECH=true` 时对对应国家/地区的请求生效
- **Meta 域名 Google 兜底**：Meta 域名 A/AAAA 解析优先走竞速池，失败时自动切换 Google DoH 直连，保证国内可用
