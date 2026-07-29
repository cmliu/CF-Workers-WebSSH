# CF-Workers-WebSSH

一个运行在 Cloudflare Workers 上的原生 WebSSH 终端。浏览器通过 HTTPS/WebSocket 连接 Worker，Worker 使用 Cloudflare TCP Sockets 直接连接公网 SSH 服务器，并在边缘运行时内完成 SSH 2.0 握手、主机密钥校验、用户认证和交互式 PTY 会话。

运行时无 SSH 第三方依赖，前端、会话网关、SSH 客户端实现和静态资源均由同一个 Worker 部署提供。

> [!IMPORTANT]
> 项目始终允许匿名创建网关会话，不提供内置访问令牌或用户身份认证。公网部署前务必使用 Cloudflare Access、WAF 与限流策略保护页面和 API，并关闭不需要的 `workers.dev` 公网入口。

## 功能特性

- Cloudflare Workers 原生部署，使用 Durable Objects 隔离每个 SSH 会话。
- 基于 xterm.js 的响应式终端，支持桌面端和移动端、自动缩放、全屏和会话日志。
- 内置 SFTP 文件管理，可浏览目录、上传/下载文件、新建与删除空目录、删除文件和重命名。
- 支持 SSH password 与单密码提示的 keyboard-interactive 认证，以及 Ed25519、RSA、ECDSA 的未加密 OpenSSH 私钥认证。
- 首次连接时暂停认证并显示主机 SHA-256 指纹，确认后才会发送 SSH 凭据。
- SSH 连接成功后自动写入浏览器本地"历史记录"，密码使用 AES-256-GCM 加密，私钥不保存。
- 支持 UTF-8、GB18030、Big5 显示编码、初始命令和分享链接（密码认证时链接携带 Base64 密码，粘贴即自动连接）。
- 提供一次性会话票据、同源检查、HTTPS 强制、安全响应头和公网目标校验。
- SSH 数据包、密钥交换、加密、认证和通道逻辑全部使用 TypeScript 与 Web Crypto 实现。

## 工作原理

```text
浏览器（xterm.js）
    │  HTTPS：申请一次性会话票据
    │  WSS：终端输入、输出和控制消息；独立 SFTP 文件通道
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

## 支持范围

| 类别 | 当前支持 |
| --- | --- |
| SSH 协议 | SSH 2.0 交互式 Shell、PTY、SFTP v3、窗口尺寸同步、Keepalive |
| 用户认证 | Password、单密码提示 keyboard-interactive、OpenSSH Ed25519、RSA、ECDSA P-256/P-384/P-521 私钥 |
| 密钥交换 | `curve25519-sha256`、`ecdh-sha2-nistp256` |
| 主机密钥 | Ed25519、ECDSA P-256/P-384/P-521、RSA SHA-2 |
| 加密算法 | AES-128/256-GCM、AES-128/192/256-CTR |
| MAC | HMAC-SHA2-256、HMAC-SHA2-512（AES-GCM 不使用独立 MAC） |
| 终端编码 | UTF-8、GB18030、Big5（取决于浏览器 `TextDecoder` 支持） |

**限制**：只能连接公网 IP 或解析结果全部为公网地址的域名；不支持出站 TCP 25 端口；不支持加密私钥、PEM/PKCS#8 私钥、SSH Agent、多因素键盘交互认证、SCP、端口转发、ProxyJump、SSH 压缩和会话内 rekey。文件上传与下载单文件限制为 64 MiB，目录删除仅支持空目录。

## 部署教程

1. Fork 该项目到用户自己的 GitHub 仓库。
2. 在 `Cloudflare` > `Workers 和 Pages` > `创建应用程序` > `Continue with GitHub` 按钮，选择已 Fork 的项目进行部署。
3. 在"构建命令"（Build Command）一栏中填入 `npm run deploy`。
4. 点击"部署"按钮即可完成部署。

## 配置项

| 名称 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CONNECT_TIMEOUT_MS` | Variable | `"10000"` | TCP 建连超时，运行时限制在 2000–30000 ms。 |
| `SSH_SESSIONS` | Durable Object binding | 已配置 | 每个连接独立的会话对象。 |
| `ASSETS` | Workers Assets binding | 已配置 | 将 `dist/` 静态资源交给 Worker 提供。 |

会话创建始终匿名，不存在用于开启、关闭或保护会话创建的项目变量。公开网关可能被滥用、产生费用或导致 Cloudflare 账户受限，应在 Cloudflare 边缘配置身份访问策略、WAF、限流和使用监控。

## 自定义域名与 Cloudflare Access

绑定自定义域名：在 Cloudflare Dashboard 的 `Workers & Pages` -> 选择 Worker -> `Settings` -> `Domains & Routes` -> `Add` -> `Custom domain` 中添加。也可在 `wrangler.toml` 中写入：

```toml
routes = [
  { pattern = "ssh.example.com", custom_domain = true }
]
```

确认自定义域名可用后，将 `workers_dev = false` 关闭公网 `workers.dev` 入口。

在 Cloudflare Zero Trust 中为自定义域名创建 Self-hosted Application，配置只允许指定用户、邮箱域或身份提供商访问。WebSocket 使用同一站点的 Access 会话，可保护整个 WebSSH 页面和 API。建议纵深防御：

- 确保所有可访问域名都受 Access 保护。
- 设置 `workers_dev = false`，避免公开 `workers.dev` 地址绕过自定义域名策略。
- 使用 WAF 规则限制异常请求和不需要的访问区域。
- 对会话申请与 WebSocket 建连路径配置限流，并设置告警。
- 验证 Access 策略同时覆盖页面、`/api/session` 与 `/api/ssh`。

## 本地开发

```bash
cp .env.example .dev.vars   # Windows: Copy-Item .env.example .dev.vars
npm run dev                 # 启动 Wrangler，访问 http://localhost:8787
```

如需前端热更新，使用两个终端：

```bash
# 终端 1
npm run build:web
npx wrangler dev

# 终端 2
npm run dev:web    # 访问 http://localhost:5173，Vite 代理 /api 到 8787
```

> [!NOTE]
> 本地 Worker 仍从你的网络连接目标 SSH 服务器，公网目标限制同样生效。不要使用生产 SSH 凭据测试不受信任的代码分支。

## 常用命令

| 命令 | 作用 |
| --- | --- |
| `npm run dev` | 通过 Wrangler 构建前端并启动本地 Worker |
| `npm run dev:web` | 启动 Vite 前端开发服务器 |
| `npm run build:web` | 将前端构建到 `dist/` |
| `npm run typecheck` | 检查 Worker 与前端 TypeScript |
| `npm run check` | 执行全部检查、构建和部署 dry-run |
| `npm run deploy` | 通过 Wrangler 构建前端并部署到 Cloudflare |

## 项目结构

```text
.
├── frontend/                  # xterm.js 前端
│   ├── index.html
│   └── src/
│       ├── main.ts            # 连接管理、xterm、WebSocket 客户端
│       ├── history.ts         # 历史记录归一化与去重
│       ├── history-key.ts     # IndexedDB 中的 AES-GCM 密钥
│       ├── password-crypto.ts # 历史密码 AES-GCM 加解密
│       ├── ui-state.ts        # 连接按钮与面板状态机
│       └── style.css
├── src/
│   ├── backend/
│   │   ├── durable-object.ts  # 会话票据、TCP Socket 与会话生命周期
│   │   ├── security.ts        # 票据、同源与公网目标校验
│   │   ├── session.ts         # SSH 状态机与浏览器消息桥接
│   │   └── sftp-handler.ts    # SFTP 文件操作与传输状态
│   ├── ssh/                   # SSH 协议、KEX、密码学、认证与通道
│   ├── http-security.ts       # HTTPS 与安全响应头
│   ├── types.ts               # Worker 环境、连接消息和 SSH 类型
│   └── worker.ts              # HTTP/API/Assets 入口
├── wrangler.toml              # Worker、Assets、Durable Object 与 migration
└── package.json
```

## API 概览

| 接口 | 方法 | 用途 |
| --- | --- | --- |
| `/api/health` | `GET` | 返回 Worker 与 SSH 功能健康状态 |
| `/api/session` | `POST` | 匿名创建一次性会话票据 |
| `/api/ssh?ticket=...&session=...` | `GET` + WebSocket Upgrade | 进入对应 Durable Object 并建立 SSH 会话 |
| `/api/sftp?session=...&token=...` | `GET` + WebSocket Upgrade | 使用一次性附着令牌进入当前会话的文件通道 |

所有 `/api/*` 响应均允许跨站访问，并支持浏览器 `OPTIONS` 预检请求。公网访问控制应由 Cloudflare Access、WAF 和限流策略提供。

## 安全说明

- 一次性票据使用随机密钥和 HMAC-SHA256 签名，绑定请求端 IP、60 秒过期并立即销毁。
- 域名解析后逐个检查公网地址，直接连接已验证 IP，限制 SSRF 与 DNS 重绑定。
- SSH 主机密钥会验证交换签名并计算 `SHA256:` 指纹；没有固定指纹时，认证会暂停等待用户确认。
- 历史密码使用 AES-256-GCM 加密，密钥保存在 IndexedDB 中，不写入 Local Storage。
- 响应设置 CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options` 等安全头。
- Worker 是实际的 SSH 客户端，密码或私钥会在 Worker 会话内存中被处理。请使用权限最小化的独立账号或密钥。

## 许可证

[Apache License 2.0](LICENSE)

## 致谢

本项目在开发过程中参考了以下优秀开源项目，特此致谢：

- [huashengdun/webssh](https://github.com/huashengdun/webssh) —— 基于 WebSocket 的 WebSSH 终端，本项目前端兼容其 `wssh` JavaScript API。
- [newbietan/CloudSSH](https://github.com/newbietan/CloudSSH) —— Cloudflare Workers 上的 SSH 实现参考。
- [crazypeace/huashengdun-webssh](https://github.com/crazypeace/huashengdun-webssh) —— huashengdun/webssh 的二次开发维护分支，为本项目前端兼容性提供了参考。
