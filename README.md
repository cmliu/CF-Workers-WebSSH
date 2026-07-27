# CF-Workers-WebSSH

一个运行在 Cloudflare Workers 上的原生 WebSSH 终端。浏览器通过 HTTPS/WebSocket 连接 Worker，Worker 使用 Cloudflare TCP Sockets 直接连接公网 SSH 服务器，并在边缘运行时内完成 SSH 2.0 握手、主机密钥校验、用户认证和交互式 PTY 会话。

项目不依赖额外的 WebSSH 后端、容器或常驻服务器；前端、会话网关、SSH 客户端实现和静态资源均由同一个 Worker 部署提供。

> [!IMPORTANT]
> 这是一个 SSH 访问网关。项目始终允许匿名创建网关会话，不提供内置的访问令牌或用户身份认证。公网部署前务必使用 Cloudflare Access、WAF 与限流策略保护页面和 API，并关闭不需要的 `workers.dev` 公网入口。

## 功能特性

- Cloudflare Workers 原生部署，使用 Durable Objects 隔离每个 SSH 会话。
- 基于 xterm.js 的响应式终端，支持桌面端和移动端、自动缩放、全屏和会话日志。
- 支持密码认证，以及 Ed25519、RSA、ECDSA 的未加密 OpenSSH 私钥认证。
- 首次连接时暂停认证并显示主机 SHA-256 指纹，确认后才会发送 SSH 凭据。
- SSH 连接成功后自动写入浏览器本地“历史记录”；条目统一以 `用户名@主机:端口` 命名，第二行显示最后连接时间。
- 历史记录可恢复连接配置、经 AES-GCM 加密的密码和主机指纹，但不保存私钥。
- 支持 UTF-8、GB18030、Big5 显示编码、初始命令和无凭据分享链接。
- 提供一次性会话票据、同源检查、HTTPS 强制、安全响应头和公网目标校验。
- 运行时无 SSH 第三方依赖，SSH 数据包、密钥交换、加密、认证和通道逻辑均使用 TypeScript 与 Web Crypto 实现。

## 工作原理

```text
浏览器（xterm.js）
    │  HTTPS：申请一次性会话票据
    │  WSS：终端输入、输出和控制消息
    ▼
Cloudflare Worker
    │  同源检查、会话票据、静态资源
    ▼
每会话 Durable Object
    │  消耗一次性票据、校验目标地址、运行 SSH 2.0 客户端
    │  Cloudflare TCP Socket
    ▼
公网 SSH 服务器
```

一次连接的主要流程如下：

1. 浏览器向 `POST /api/session` 匿名申请一次性会话票据。
2. Worker 创建独立 Durable Object，并签发一个有效期 60 秒、绑定客户端地址且只能使用一次的票据。
3. 浏览器携带票据连接 `GET /api/ssh` WebSocket；Durable Object 消耗票据。
4. Worker 解析目标域名，通过 Cloudflare DNS over HTTPS 获取 A/AAAA 记录，拒绝私有、保留或本地地址。
5. Durable Object 只连接已经通过校验的 IP，避免 DNS 重绑定，然后在该 TCP 连接上执行 SSH 协议。
6. 主机密钥签名验证成功后，浏览器确认或比对固定指纹；只有通过后才发送用户认证数据。
7. 认证成功后建立 PTY 和交互式 Shell，浏览器与 SSH 通道之间开始转发终端数据，并将该目标更新到浏览器历史记录。

## 支持范围

| 类别 | 当前支持 |
| --- | --- |
| SSH 协议 | SSH 2.0 交互式 Shell、PTY、窗口尺寸同步、Keepalive |
| 用户认证 | Password、OpenSSH Ed25519、RSA、ECDSA P-256/P-384/P-521 私钥 |
| 密钥交换 | `curve25519-sha256`、`ecdh-sha2-nistp256` |
| 主机密钥 | Ed25519、ECDSA P-256/P-384/P-521、RSA SHA-2 |
| 加密算法 | AES-128/256-GCM、AES-128/192/256-CTR |
| MAC | HMAC-SHA2-256、HMAC-SHA2-512（AES-GCM 不使用独立 MAC） |
| 压缩 | 仅 `none` |
| 终端编码 | UTF-8、GB18030、Big5（取决于浏览器 `TextDecoder` 支持） |

当前限制：

- 只能连接公网 IP 或解析结果全部为公网地址的域名；内网、回环、链路本地、保留地址和 `.internal` 目标会被拒绝。
- Cloudflare Workers 不允许连接出站 TCP 25 端口，本项目也会提前拒绝该端口。
- 不支持加密私钥、PEM/PKCS#8 私钥文件；私钥必须是 `BEGIN OPENSSH PRIVATE KEY` 格式，且前端限制为 64 KiB。
- 不支持 SSH Agent、键盘交互认证、多因素认证、证书认证、SFTP/SCP、端口转发和 ProxyJump。
- 不支持 SSH 压缩和会话内重新密钥交换（rekey）。服务端主动 rekey 时当前会话会断开，需要重新连接。
- 每个浏览器页面同时维护一个活动 SSH 会话。Worker 更新或 Durable Object 重启时，活动会话需要重新连接。

## 安全说明

### 已实现的保护

- 一次性票据使用随机密钥和 HMAC-SHA256 签名；会话申请始终匿名，票据本身不代表用户身份认证。
- 会话票据绑定请求端 IP、60 秒过期并在第一次使用尝试时立即销毁，降低重放风险。
- API 和 WebSocket 必须来自页面同源 `Origin`；Cloudflare 边缘上的 HTTP API 请求会被拒绝，页面请求会重定向至 HTTPS。
- 域名解析后逐个检查公网地址，并直接连接已验证 IP，以限制 SSRF 与 DNS 重绑定。
- SSH 主机密钥会验证交换签名并计算 `SHA256:` 指纹；没有固定指纹时，认证会暂停等待用户确认。
- SSH 连接成功后，连接配置会自动写入浏览器 Local Storage 的“历史记录”。密码使用 AES-256-GCM 加密，Local Storage 仅保存密码密文、随机 IV 和格式版本；随机生成的不可导出密钥保存在当前站点的 IndexedDB 中，不写入 Local Storage。密钥缺失、不匹配或密文校验失败时，历史记录仍会载入，但密码字段保持为空。私钥不会写入浏览器存储，任何 SSH 凭据都不会写入 Durable Object 存储。凭据输入框在发起授权后立即清空，Worker 在生成认证请求后释放凭据引用。
- 响应设置 CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options` 等安全头。

### 信任边界

浏览器到 Cloudflare 使用 TLS，Cloudflare Worker 到目标服务器使用 SSH 加密。Worker 是实际的 SSH 客户端，因此密码或私钥会在 Worker 会话内存中被处理；这不是浏览器到目标主机的端到端 SSH。请自行部署、保护 Cloudflare 账户，并为 WebSSH 使用权限最小化的独立账号或密钥。

历史密码密钥绑定的是当前站点下的浏览器配置，而不是可证明唯一的物理设备身份。AES-GCM 存储保护主要用于防止攻击者只窃取 Local Storage 后直接读取密码；它不能防御同源 XSS、具有站点数据访问权限的恶意浏览器扩展，或连同 IndexedDB 在内的完整浏览器配置被窃取。清除或迁移部分站点数据、切换浏览器配置后，原有密码可能无法解密并会显示为空。

第一次出现的主机指纹不能仅凭页面显示就判定可信。应通过服务器控制台、可信管理员或已有的安全通道核对。例如在 SSH 服务器上查看 Ed25519 主机密钥指纹：

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

## 历史记录

页面不提供单独的“保存”按钮。只有 SSH 连接成功后，目标才会自动新增或更新到当前浏览器的“历史记录”：

- 名称固定为 `用户名@主机:端口`，例如 `root@ssh.example.com:22`，不再填写自定义连接名称。
- 每个条目的第二行只显示最后连接时间；再次成功连接同一条目时会更新时间。
- 点击历史条目会恢复主机、端口、用户名、认证方式和其他已保存选项，便于随时重新连接。
- 密码使用 AES-256-GCM 加密；Local Storage 只保存密文、随机 IV 和格式版本，不保存密码明文或解密密钥。不可导出的随机密钥保存在当前站点的 IndexedDB 中。
- 解密密钥缺失、不匹配或密文被修改时，连接配置仍会恢复，但密码字段保持为空，需要重新输入；私钥始终不保存，使用私钥认证时需要重新选择或粘贴。
- 历史记录和密码密钥属于当前浏览器配置及当前站点来源，并不代表绝对唯一的物理设备。清除站点数据、使用隐私浏览窗口、更换浏览器配置或域名后，原有记录可能丢失或密码无法解密。

## 部署教程：Wrangler CLI（推荐）

### 1. 准备条件

部署前需要：

- 一个 Cloudflare 账户，并已启用 Workers 与 Durable Objects。
- Node.js `22.12.0` 或更高版本，以及 npm。
- 一台具有公网 IP 或公网 DNS 记录、可从 Cloudflare 网络访问的 SSH 服务器。
- 目标 SSH 服务至少支持上表中的一组密钥交换、主机密钥和加密算法。

检查本机版本：

```bash
node --version
npm --version
```

### 2. 获取代码并安装依赖

```bash
git clone https://github.com/cmliu/CF-Workers-WebSSH.git
cd CF-Workers-WebSSH
npm ci
```

如果部署自己的 Fork，请将 clone 地址替换为你的仓库地址。

### 3. 登录 Cloudflare

```bash
npx wrangler login
npx wrangler whoami
```

`wrangler login` 会打开浏览器完成 OAuth 授权。无浏览器的 CI 环境应使用权限最小化的 Cloudflare API Token，并通过 CI Secret 提供 `CLOUDFLARE_API_TOKEN`，不要把 Token 写进仓库。

### 4. 检查 Worker 配置

默认配置位于 [`wrangler.toml`](wrangler.toml)：

```toml
name = "cf-workers-webssh"
main = "src/worker.ts"
compatibility_date = "2026-07-01"
workers_dev = true

[assets]
directory = "./dist"
binding = "ASSETS"
not_found_handling = "single-page-application"
run_worker_first = true

[vars]
CONNECT_TIMEOUT_MS = "10000"
```

可以修改 `name`，它决定默认的 `*.workers.dev` 子域名。请保留 `SSH_SESSIONS` Durable Object binding 和 `v1` migration；首次部署会用它创建 `SSHSessionDO` SQLite 类。

### 5. 完整检查

```bash
npm run check
```

该命令依次执行 Worker 与前端类型检查、Node 单元测试、Cloudflare 运行时测试、前端构建和 Wrangler dry-run。任何一步失败都应先修复，不建议跳过后直接部署。

也可以单独运行：

```bash
npm run typecheck
npm test
npm run test:edge
npm run build:web
```

### 6. 首次发布

```bash
npm run deploy
```

`deploy` 会调用 Wrangler；`wrangler.toml` 中的构建钩子先把前端构建到 `dist/`，再上传 Worker、静态资源、Durable Object binding 和 migration。成功后终端会输出类似地址：

```text
https://cf-workers-webssh.<your-subdomain>.workers.dev
```

部署完成后，页面和会话接口都可以直接访问。项目不会要求配置网关令牌；在公开地址验证 SSH 连接前，请先按后文配置 Cloudflare Access、WAF 与限流规则。

### 7. 验证部署

先检查健康接口：

```bash
curl https://cf-workers-webssh.<your-subdomain>.workers.dev/api/health
```

预期返回：

```json
{"status":"ok","runtime":"cloudflare-workers","ssh":true}
```

然后在浏览器打开 Worker 地址：

1. 输入 SSH 公网主机、端口和用户名。
2. 选择密码或 SSH 密钥认证并输入凭据。
3. 点击“连接”。第一次连接时，通过可信渠道核对页面显示的 SHA-256 主机指纹。
4. 确认后进入交互式 Shell；连接成功的目标会自动进入“历史记录”。若勾选记住指纹，后续连接会在当前浏览器中自动固定并比对。

### 8. 更新部署

```bash
git pull --ff-only
npm ci
npm run check
npm run deploy
```

更新前建议阅读代码差异，尤其是 `wrangler.toml` 中的 Durable Object migration。不要删除已经发布过的 migration tag，也不要随意修改已部署 Durable Object 的类名。

## 配置项

| 名称 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CONNECT_TIMEOUT_MS` | Variable | `"10000"` | 每个已验证目标 IP 的 TCP 建连超时，运行时会限制在 2000 到 30000 ms。 |
| `SSH_SESSIONS` | Durable Object binding | 已配置 | 每个连接独立的会话对象。不要改名，除非同时修改代码与 migration。 |
| `ASSETS` | Workers Assets binding | 已配置 | 将 `dist/` 静态资源交给 Worker 提供。 |

普通变量可以编辑 `wrangler.toml` 后重新部署。会话创建始终匿名，不存在用于开启、关闭或保护会话创建的项目变量。公开网关可能被滥用、产生费用或导致 Cloudflare 账户受限，应在 Cloudflare 边缘配置身份访问策略、WAF、限流和使用监控。

### 从旧版本升级

旧版本部署中可能仍残留已废弃的网关访问 Secret 或匿名开关。新版本会忽略这些值，它们不会继续提供访问保护；请在 Worker 的 `Settings` -> `Variables and Secrets` 中手动清理对应的旧 Secret 和变量，避免产生仍受保护的错误判断。升级并开放流量前，先确认 Cloudflare Access、WAF、限流规则及所有可访问域名均已正确配置。

## 自定义域名与 Cloudflare Access

### 绑定自定义域名

在 Cloudflare Dashboard 中进入：

`Workers & Pages` -> 选择该 Worker -> `Settings` -> `Domains & Routes` -> `Add` -> `Custom domain`

输入同一 Cloudflare 账户下 Zone 中的域名，例如 `ssh.example.com`。Cloudflare 会创建路由并签发 HTTPS 证书，生效后用以下地址检查：

```bash
curl https://ssh.example.com/api/health
```

也可以将路由写入 `wrangler.toml` 后部署：

```toml
routes = [
  { pattern = "ssh.example.com", custom_domain = true }
]
```

确认自定义域名可用后，如果不希望用户绕过自定义域名访问 `workers.dev`，将配置改为：

```toml
workers_dev = false
```

然后再次执行 `npm run deploy`。关闭前先确认自定义域名和 Access 策略工作正常，避免把自己锁在外面。

### 使用 Cloudflare Access

可在 Cloudflare Zero Trust 中为 `ssh.example.com` 创建 Self-hosted Application，并配置只允许指定用户、邮箱域或身份提供商访问。WebSocket 使用同一站点的 Access 会话，适合保护整个 WebSSH 页面和 API。

本项目自身不提供身份认证，建议采用以下纵深防御：

- 确保所有可访问域名都受 Access 保护。
- 设置 `workers_dev = false`，避免公开的 `workers.dev` 地址绕过自定义域名策略。
- 使用 WAF 规则限制异常请求、已知恶意来源和不需要的访问区域。
- 对会话申请与 WebSocket 建连路径配置限流，并结合 Worker、Durable Objects 和网络使用量监控设置告警。
- 验证 Access 策略同时覆盖页面、`/api/session` 与 `/api/ssh`；同源检查和一次性票据不能替代用户身份认证。

## 通过 Cloudflare Git 集成部署

不想在本机运行 Wrangler 时，可以使用 Cloudflare 的 Git 集成：

1. 将项目 Fork 到自己的 GitHub 或 GitLab 账户。
2. 在 Cloudflare Dashboard 中进入 `Workers & Pages`，选择创建 Worker 并导入 Git 仓库。
3. 项目根目录使用 `/`，Node.js 版本选择 22 或更高。
4. Build command 留空；`wrangler.toml` 中的 `[build]` 会自动执行 `npm run build:web`。
5. Deploy command 设置为 `npx wrangler deploy` 或 `npm run deploy`，两者都会通过同一个 Wrangler 构建钩子生成前端资源。
6. 首次部署完成后，配置 Cloudflare Access、WAF、限流规则，并确认没有不受保护的公开域名。
7. 按前文方式检查 `/api/health` 与实际 SSH 连接。

Dashboard 的菜单名称可能随 Cloudflare UI 更新而略有变化。关键点是：`wrangler.toml` 必须参与部署，其 `[build]` 配置会在 Wrangler 读取 `dist/` 前生成前端资源；访问控制必须配置在 Cloudflare 边缘并覆盖所有公开入口。

## 本地开发

### 创建本地变量文件

复制示例文件为 `.dev.vars`：

Linux/macOS：

```bash
cp .env.example .dev.vars
```

Windows PowerShell：

```powershell
Copy-Item .env.example .dev.vars
```

编辑 `.dev.vars`：

```dotenv
CONNECT_TIMEOUT_MS=10000
```

`.dev.vars` 已被 `.gitignore` 忽略。不要提交 SSH 密码、私钥或其他真实凭据。

### 启动完整本地环境

```bash
npm run dev
```

该命令启动 Wrangler，Wrangler 会先通过 `[build]` 构建前端，默认访问 `http://localhost:8787`。本地回环地址允许 HTTP，生产边缘请求仍强制 HTTPS。

如需前端热更新，使用两个终端：

终端 1：

```bash
npm run build:web
npx wrangler dev
```

终端 2：

```bash
npm run dev:web
```

然后访问 `http://localhost:5173`。Vite 会把 `/api` HTTP 和 WebSocket 请求代理到本地 Wrangler 的 `8787` 端口。

> [!NOTE]
> 本地 Worker 仍然从你的网络连接目标 SSH 服务器；公网目标限制同样生效。不要使用生产 SSH 凭据测试不受信任的代码分支。

### 常用命令

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | 通过 Wrangler 构建前端并启动本地 Worker |
| `npm run dev:web` | 启动 Vite 前端开发服务器 |
| `npm run build:web` | 将前端构建到 `dist/` |
| `npm run typecheck` | 检查 Worker 与前端 TypeScript |
| `npm test` | 运行 Node 环境单元测试 |
| `npm run test:edge` | 在 Cloudflare Workers 测试池运行边缘加密与安全测试 |
| `npm run check` | 执行全部检查、构建和部署 dry-run |
| `npm run deploy` | 通过 Wrangler 构建前端并部署到 Cloudflare |

## 项目结构

```text
.
├── frontend/
│   ├── index.html             # WebSSH 页面
│   └── src/
│       ├── main.ts            # xterm、连接状态、配置与 WebSocket 客户端
│       └── style.css          # 响应式界面样式
├── src/
│   ├── backend/
│   │   ├── durable-object.ts  # 会话票据、TCP Socket 与会话生命周期
│   │   ├── security.ts        # 票据、同源与公网目标校验
│   │   └── session.ts         # SSH 状态机与浏览器消息桥接
│   ├── ssh/                   # SSH 协议、KEX、密码学、认证与通道实现
│   ├── http-security.ts       # HTTPS 与安全响应头
│   ├── types.ts               # Worker 环境、连接消息和 SSH 类型
│   └── worker.ts              # HTTP/API/Assets 入口
├── tests/                     # Node 单元测试
├── tests-edge/                # Cloudflare 运行时测试
├── wrangler.toml              # Worker、Assets、Durable Object 与 migration
├── vite.config.ts             # 前端构建配置
└── package.json               # 脚本与依赖
```

## API 概览

这些接口供同源前端使用，不建议作为稳定的公共 API：

| 接口 | 方法 | 用途 |
| --- | --- | --- |
| `/api/health` | `GET` | 返回 Worker 与 SSH 功能健康状态 |
| `/api/session` | `POST` | 匿名创建一次性会话票据 |
| `/api/ssh?ticket=...&session=...` | `GET` + WebSocket Upgrade | 进入对应 Durable Object 并建立 SSH 会话 |

`/api/session` 和 `/api/ssh` 都要求请求 `Origin` 与 Worker URL 同源。票据包含敏感授权能力且只能短时使用，不应记录、复用或转发。同源检查只限制浏览器请求来源，不验证用户身份；公网访问控制应由 Cloudflare Access、WAF 和限流策略提供。

## 常见问题

### 为什么任何访问者都能申请会话票据

这是项目的预期行为：会话创建始终匿名，一次性票据仅用于把短时请求安全地交给对应 Durable Object，不承担用户身份认证。公网部署必须使用 Cloudflare Access 限制访问者，并配合 WAF、限流和监控降低扫描、滥用与费用风险。

### `403 Invalid request origin` / `Invalid WebSocket origin`

API 只能由同源页面调用。检查是否通过反向代理改写了 `Origin`、协议或 Host，也不要从其他站点直接调用接口。公网部署必须使用 HTTPS/WSS。

### `Private and reserved SSH targets are disabled`

目标是内网/保留 IP，或者 DNS 同时解析到公网和私网地址。当前项目有意不提供内网穿透。如果需要访问私网主机，应使用受控 VPN、Cloudflare Tunnel 配合专门的访问架构，或在私网内运行其他 SSH 网关，而不是关闭此校验。

### TCP 连接超时或被拒绝

- 确认主机和端口在公网可达，SSH 服务确实监听该端口。
- 检查云防火墙、安全组、主机防火墙和入站白名单。
- Cloudflare Workers TCP 出口不提供可由本项目固定的单一源 IP；只允许家庭或办公出口 IP 的白名单通常会拒绝连接。
- 端口 25 无法使用。需要更长建连时间时，可将 `CONNECT_TIMEOUT_MS` 调高到最多 `30000`。

### 没有共同的 KEX、Host Key、Cipher 或 MAC

目标 SSH 服务器没有启用本项目支持的算法。优先在服务端启用现代算法，例如 `curve25519-sha256`、Ed25519/ECDSA/RSA-SHA2 主机密钥和 AES-GCM/CTR。不要为了兼容而重新启用 `ssh-rsa` SHA-1、过时 CBC 或弱 KEX；本项目不会协商这些算法。

### 私钥无法使用

- 必须以 `-----BEGIN OPENSSH PRIVATE KEY-----` 开头，而不是 `BEGIN RSA PRIVATE KEY` 或 `BEGIN PRIVATE KEY`。
- 私钥不能有口令，且大小不能超过 64 KiB。
- 建议新建仅供此网关使用、权限最小化的 Ed25519 密钥，不要移除日常主密钥的口令。

创建一个无口令的专用 Ed25519 密钥：

```bash
ssh-keygen -t ed25519 -f webssh_ed25519 -N ""
```

将 `webssh_ed25519.pub` 安装到目标账户的 `~/.ssh/authorized_keys`，页面中只使用私钥文件 `webssh_ed25519`。妥善限制目标账户权限并安全保管私钥。

### 主机密钥不匹配

服务器重装、SSH 主机密钥轮换或 DNS 指向变化都可能导致不匹配，也可能代表中间人攻击。不要直接删除已保存指纹；先通过可信渠道核对新指纹。确认是合法轮换后，再更新高级选项中的指纹或清除该站点保存的主机指纹。

### 会话运行一段时间后因 rekey 断开

当前实现不支持 SSH rekey。达到服务端的时间或流量阈值后，需要重新连接。只有在了解安全影响并符合组织策略时，才考虑调整服务端 `RekeyLimit`；更推荐保留合理阈值并接受会话重连。

### Worker 更新时会话断开

这是预期行为。部署新版本或 Durable Object 被重新调度后，现有 SSH 流状态无法恢复，浏览器会收到重连提示。部署前请避免在 WebSSH 中运行无法恢复的重要前台任务，或先进入 `tmux`/`screen`。

## 运维建议

- 使用 Cloudflare Access 保护所有公开域名，配置 WAF 与会话接口限流，并关闭不需要的 `workers.dev` 公网入口。
- 为 WebSSH 创建独立、低权限 SSH 账户和密钥；敏感运维使用 `sudo` 审计与最小授权。
- 开启 Cloudflare 账户 MFA，定期审查 Access 策略、WAF 与限流规则，并限制部署 API Token 权限。
- 监控 Worker、Durable Objects 和网络使用量。每个活动终端都会占用 Durable Object 与出站 TCP 连接，费用和限制以 Cloudflare 当前套餐为准。
- 更新前执行 `npm run check`，保留已经发布的 Durable Object migrations，并在低峰期部署。
- 不要在 URL、Issue、日志、截图或分享链接中放入密码、私钥或一次性票据。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
