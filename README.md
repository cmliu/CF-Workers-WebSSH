# CF-Workers-WebSSH

一个运行在 Cloudflare Workers 上的原生 WebSSH 终端。浏览器通过 HTTPS/WebSocket 连接 Worker，Worker 使用 Cloudflare TCP Sockets 直接连接公网 SSH 服务器，并在边缘运行时内完成 SSH 2.0 握手、主机密钥校验、用户认证和交互式 PTY 会话。

项目不依赖额外的 WebSSH 后端、容器或常驻服务器；前端、会话网关、SSH 客户端实现和静态资源均由同一个 Worker 部署提供。

> [!IMPORTANT]
> 这是一个 SSH 访问网关。部署者能够控制 Worker 代码和运行时配置，请只使用自己信任的部署。生产环境务必设置 `ACCESS_TOKEN` 或使用等效的 Cloudflare Access 保护，不要直接开放匿名访问。

## 功能特性

- Cloudflare Workers 原生部署，使用 Durable Objects 隔离每个 SSH 会话。
- 基于 xterm.js 的响应式终端，支持桌面端和移动端、自动缩放、全屏和会话日志。
- 支持密码认证，以及 Ed25519、RSA、ECDSA 的未加密 OpenSSH 私钥认证。
- 首次连接时暂停认证并显示主机 SHA-256 指纹，确认后才会发送 SSH 凭据。
- 可在浏览器本地保存连接配置和主机指纹，但不保存密码、私钥或网关令牌。
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
    │  同源检查、ACCESS_TOKEN 校验、静态资源
    ▼
每会话 Durable Object
    │  消耗一次性票据、校验目标地址、运行 SSH 2.0 客户端
    │  Cloudflare TCP Socket
    ▼
公网 SSH 服务器
```

一次连接的主要流程如下：

1. 浏览器向 `POST /api/session` 提交网关访问令牌。
2. Worker 创建独立 Durable Object，并签发一个有效期 60 秒、绑定客户端地址且只能使用一次的票据。
3. 浏览器携带票据连接 `GET /api/ssh` WebSocket；Durable Object 消耗票据。
4. Worker 解析目标域名，通过 Cloudflare DNS over HTTPS 获取 A/AAAA 记录，拒绝私有、保留或本地地址。
5. Durable Object 只连接已经通过校验的 IP，避免 DNS 重绑定，然后在该 TCP 连接上执行 SSH 协议。
6. 主机密钥签名验证成功后，浏览器确认或比对固定指纹；只有通过后才发送用户认证数据。
7. 认证成功后建立 PTY 和交互式 Shell，浏览器与 SSH 通道之间开始转发终端数据。

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

- 默认关闭：未配置 `ACCESS_TOKEN` 且 `ALLOW_ANONYMOUS` 不为 `true` 时，会话接口返回 `503`。
- `ACCESS_TOKEN` 使用恒定时间比较；一次性票据使用随机密钥和 HMAC-SHA256 签名。
- 会话票据绑定请求端 IP、60 秒过期并在第一次使用尝试时立即销毁，降低重放风险。
- API 和 WebSocket 必须来自页面同源 `Origin`；Cloudflare 边缘上的 HTTP API 请求会被拒绝，页面请求会重定向至 HTTPS。
- 域名解析后逐个检查公网地址，并直接连接已验证 IP，以限制 SSRF 与 DNS 重绑定。
- SSH 主机密钥会验证交换签名并计算 `SHA256:` 指纹；没有固定指纹时，认证会暂停等待用户确认。
- 密码、私钥和网关令牌不会写入 Local Storage 或 Durable Object 存储。连接表单在发起授权后立即清空，Worker 在生成认证请求后释放凭据引用。
- 响应设置 CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options` 等安全头。

### 信任边界

浏览器到 Cloudflare 使用 TLS，Cloudflare Worker 到目标服务器使用 SSH 加密。Worker 是实际的 SSH 客户端，因此密码或私钥会在 Worker 会话内存中被处理；这不是浏览器到目标主机的端到端 SSH。请自行部署、保护 Cloudflare 账户，并为 WebSSH 使用权限最小化的独立账号或密钥。

第一次出现的主机指纹不能仅凭页面显示就判定可信。应通过服务器控制台、可信管理员或已有的安全通道核对。例如在 SSH 服务器上查看 Ed25519 主机密钥指纹：

```bash
sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

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
ALLOW_ANONYMOUS = "false"
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

此时尚未设置 `ACCESS_TOKEN`，因此页面和健康接口可以访问，但默认 `ALLOW_ANONYMOUS = "false"` 会阻止创建 SSH 会话。这是安全的初始状态。

### 7. 设置网关访问令牌

先生成一个足够长的随机值。下面的命令适用于 Node.js：

```bash
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

然后以 Cloudflare Secret 方式保存，按提示粘贴刚生成的值：

```bash
npx wrangler secret put ACCESS_TOKEN
```

Wrangler 会为已部署的 Worker 创建并激活包含该 Secret 的新版本。Secret 不会出现在 `wrangler.toml` 或构建产物中。此后每次在页面连接时，需要在“高级选项 / Advanced options”的“网关访问令牌”中输入同一个值。

如需轮换令牌，重新运行 `npx wrangler secret put ACCESS_TOKEN` 即可。删除令牌使用：

```bash
npx wrangler secret delete ACCESS_TOKEN
```

删除后，在默认 `ALLOW_ANONYMOUS = "false"` 配置下网关会安全地停止签发会话票据。

### 8. 验证部署

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
3. 展开“高级选项”，输入 `ACCESS_TOKEN`。
4. 点击“连接”。第一次连接时，通过可信渠道核对页面显示的 SHA-256 主机指纹。
5. 确认后进入交互式 Shell。若勾选记住指纹，后续连接会在当前浏览器中自动固定并比对。

### 9. 更新部署

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
| `ACCESS_TOKEN` | Secret | 未设置 | 推荐的网关访问令牌。只要设置了它，每次创建会话都必须提交正确令牌。 |
| `ALLOW_ANONYMOUS` | Variable | `"false"` | 仅在没有 `ACCESS_TOKEN` 时生效；只有精确设置为字符串 `"true"` 才允许匿名创建会话。 |
| `CONNECT_TIMEOUT_MS` | Variable | `"10000"` | 每个已验证目标 IP 的 TCP 建连超时，运行时会限制在 2000 到 30000 ms。 |
| `SSH_SESSIONS` | Durable Object binding | 已配置 | 每个连接独立的会话对象。不要改名，除非同时修改代码与 migration。 |
| `ASSETS` | Workers Assets binding | 已配置 | 将 `dist/` 静态资源交给 Worker 提供。 |

普通变量可以编辑 `wrangler.toml` 后重新部署。敏感值必须使用 `wrangler secret` 或 Cloudflare Dashboard 的加密 Secret，不要放进 `[vars]`。

### 匿名模式（不推荐用于公网）

如果明确接受任何访问者都能借助你的 Worker 发起公网 SSH TCP 连接，可以删除 `ACCESS_TOKEN` 并修改：

```toml
[vars]
ALLOW_ANONYMOUS = "true"
CONNECT_TIMEOUT_MS = "10000"
```

随后重新运行 `npm run deploy`。公开网关可能被滥用、产生费用或导致 Cloudflare 账户被限制；至少应配合 Cloudflare Access、限流策略和使用监控。

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

建议采用纵深防御：Cloudflare Access 与 `ACCESS_TOKEN` 同时开启。如果选择只依赖 Access：

- 确保所有可访问域名都受 Access 保护。
- 设置 `workers_dev = false`，避免公开的 `workers.dev` 地址绕过自定义域名策略。
- 删除 `ACCESS_TOKEN` 后才需要设置 `ALLOW_ANONYMOUS = "true"`，否则项目自身仍会拒绝签发会话。
- 不要仅在前端隐藏令牌输入框；真正的访问控制必须位于 Cloudflare Access 或 Worker 服务端。

## 通过 Cloudflare Git 集成部署

不想在本机运行 Wrangler 时，可以使用 Cloudflare 的 Git 集成：

1. 将项目 Fork 到自己的 GitHub 或 GitLab 账户。
2. 在 Cloudflare Dashboard 中进入 `Workers & Pages`，选择创建 Worker 并导入 Git 仓库。
3. 项目根目录使用 `/`，Node.js 版本选择 22 或更高。
4. Build command 留空；`wrangler.toml` 中的 `[build]` 会自动执行 `npm run build:web`。
5. Deploy command 设置为 `npx wrangler deploy` 或 `npm run deploy`，两者都会通过同一个 Wrangler 构建钩子生成前端资源。
6. 首次部署完成后，在 Worker 的 `Settings` -> `Variables and Secrets` 中新增加密 Secret：`ACCESS_TOKEN`。
7. 再次触发部署，并按前文方式检查 `/api/health` 与实际 SSH 连接。

Dashboard 的菜单名称可能随 Cloudflare UI 更新而略有变化。关键点是：`wrangler.toml` 必须参与部署，其 `[build]` 配置会在 Wrangler 读取 `dist/` 前生成前端资源；`ACCESS_TOKEN` 必须是运行时 Secret 而不是公开构建变量。

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
ACCESS_TOKEN=replace-with-a-long-random-value
ALLOW_ANONYMOUS=false
CONNECT_TIMEOUT_MS=10000
```

`.dev.vars` 已被 `.gitignore` 忽略。不要提交真实令牌、SSH 密码或私钥。

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
│   │   ├── security.ts        # Token、票据、同源与公网目标校验
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
| `/api/session` | `POST` | 校验 `ACCESS_TOKEN` 并创建一次性会话票据 |
| `/api/ssh?ticket=...&session=...` | `GET` + WebSocket Upgrade | 进入对应 Durable Object 并建立 SSH 会话 |

`/api/session` 和 `/api/ssh` 都要求请求 `Origin` 与 Worker URL 同源。票据包含敏感授权能力且只能短时使用，不应记录、复用或转发。

## 常见问题

### `503 Gateway access is not configured`

没有配置 `ACCESS_TOKEN`，且 `ALLOW_ANONYMOUS` 不是 `"true"`。生产环境运行 `npx wrangler secret put ACCESS_TOKEN`；本地开发则检查 `.dev.vars`。

### `401 Invalid access token`

页面输入的网关令牌与 Worker Secret 不一致。重新输入，或使用 `npx wrangler secret put ACCESS_TOKEN` 轮换。连接发起后令牌输入框会被清空，这是预期行为。

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

- 使用 Cloudflare Access 和 `ACCESS_TOKEN` 双重保护，关闭不需要的 `workers.dev` 公网入口。
- 为 WebSSH 创建独立、低权限 SSH 账户和密钥；敏感运维使用 `sudo` 审计与最小授权。
- 定期轮换 `ACCESS_TOKEN`，开启 Cloudflare 账户 MFA，并限制部署 API Token 权限。
- 监控 Worker、Durable Objects 和网络使用量。每个活动终端都会占用 Durable Object 与出站 TCP 连接，费用和限制以 Cloudflare 当前套餐为准。
- 更新前执行 `npm run check`，保留已经发布的 Durable Object migrations，并在低峰期部署。
- 不要在 URL、Issue、日志、截图或分享链接中放入密码、私钥、网关令牌或一次性票据。

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。
