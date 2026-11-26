<h1 align="center">Fogmals DWeb Proxy</h1>

<p align="center">
  Bring Web3 domains to your everyday browser.<br>
  让 Web3 域名走进熟悉的浏览器。
</p>

<p align="center">By Gakmots &amp; Codex</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.2.9-4c1" alt="Version 0.2.9">
  <img src="https://img.shields.io/badge/Go-1.27.3%2B-007ec6" alt="Go 1.27.3+">
  <img src="https://hub.xerj.org/contributors/Gakmots/badge.svg" alt="XERJ Corpus Hub contributor">
</p>

<p align="center">
  <a href="#english">English</a> · <a href="#简体中文">简体中文</a>
</p>

## English

**Fogmals DWeb Proxy (`dwebproxy`)** is a lightweight, modular local proxy for the decentralized web, written in Go. It resolves ENS and SNS content records locally using configured RPC endpoints, retrieves content through compatible gateways, and forwards TON requests to an existing TON Proxy.

Browse Web3 websites using a familiar browser while keeping the original domain in the address bar, such as `https://example.eth/docs/`. No custom browser or system DNS configuration is required; simply configure your browser to use the local proxy.

### Features

- **Web3 domain support** — ENS (`.eth`), SNS (`.sns`) and TON (`.ton`).
- **Multiple content networks** — IPFS, IPNS, Arweave and Swarm, with configurable gateways.
- **Flexible proxy integration** — HTTP or SOCKS5 inbound proxy; HTTP(S) and SOCKS5 upstream proxies.
- **Local HTTPS** — User-managed CA, local TLS termination for supported Web3 domains, and browser-side HTTP/2 (with HTTP/1.1 support).
- **Conventional web access** — Optional fallback proxy for ordinary HTTP requests and transparent HTTPS tunnels without TLS interception.
- **Configurable resolution and routing** — SNS record priorities, gateway failover, resolution caching and optional outbound proxy with automatic local/private-address bypass.

### Supported domains

| Domain | Resolution | Content / forwarding |
| --- | --- | --- |
| `.eth` | ENS Universal Resolver, ENSIP-15, CCIP Read, `contenthash` | IPFS / IPNS / Arweave / Swarm |
| `.sns` | Solana RPC, SNS Records V2 | IPFS / IPNS / Arweave (configurable priority) |
| `.ton` | External TON Proxy | HTTP forwarding |
| Other domains / IPs | No on-chain resolution | Optional fallback proxy |

All routing is handled internally through a single local proxy entry point.

### Quick start

**Requirements:** Go 1.27.3 or later to build from source, and working RPC endpoints, content gateways or upstream proxies for the networks you want to access. These external services are not bundled.

From the repository root:

```bash
go build -o dwebproxy ./cmd/dwebproxy
cp config.example.json config.json
./dwebproxy -config config.json -init-ca
./dwebproxy -config config.json
```

The commands above use a POSIX shell. Initialize the CA only once per installation; existing CA files are not overwritten.

Web3 HTTPS is enabled by default. Import **`certs/ca.pem`** into your browser or system's trusted root certificate store before accessing Web3 HTTPS sites. Never share, upload or import the private key `certs/ca-key.pem`.

Configure your browser's manual HTTP proxy to `127.0.0.1:18080` for both HTTP and HTTPS destinations. Disable old PAC settings if upgrading from an earlier version.

Then open a Web3 domain with a valid content record, or test with curl:

```bash
curl --noproxy '' -x http://127.0.0.1:18080 http://example.eth/
```

`example.eth` is a placeholder and may not host accessible content.

### Configuration

Edit [`config.example.json`](config.example.json) (or its copy, `config.json`). Configuration uses strict JSON; omitted fields retain their defaults. Restart the proxy after making changes.

| Option | Default / purpose |
| --- | --- |
| `listen` | `127.0.0.1:18080` (loopback only) |
| `listen_protocol` | `http`; alternatively `socks5` |
| `ethereum_rpc`, `solana_rpc` | Public RPC endpoints; configurable |
| `record_priority` | ENS: ContentHash; SNS: IPFS → IPNS → Arweave |
| `ipfs_gateways` | `http://localhost:8080` |
| `arweave_gateways` | `http://localhost:1984` |
| `swarm_gateways` | `http://localhost:1633` |
| `ton_proxy` | Empty; configure an existing TON Proxy to enable `.ton` access |
| `fallback_proxy` | Empty; configure an upstream proxy for ordinary websites |
| `program_proxy` | Disabled; optional outbound proxy for RPC, gateways and upstream connections |
| `https.enabled` | `true`; controls Web3 local HTTPS only |

IPFS/IPNS requires a **subdomain gateway** with a DNS hostname (e.g. `localhost`, not `127.0.0.1`). For Kubo, enable subdomain support and restart it:

```bash
ipfs config --json Gateway.PublicGateways.localhost '{"Paths":["/ipfs","/ipns"],"UseSubdomains":true}'
```

Arweave websites require a gateway supporting Path Manifests; Swarm requires a compatible Bee content gateway. No public content gateway fallback is enabled by default.

To use a SOCKS5 entry point, set `listen_protocol` to `socks5` and enable remote DNS in your browser (or use `socks5h://` with curl). TON and fallback upstreams may independently use HTTP(S) or SOCKS5.

To run without a local CA, set `https.enabled` to `false` and use `http://` for Web3 sites. Ordinary HTTPS remains available through a configured fallback proxy.

Useful commands:

```bash
./dwebproxy -print-config
./dwebproxy -config config.json -check
```

### Security and limitations

- ENS/SNS content is read-only (GET/HEAD). This is a browsing proxy, not a wallet or blockchain node.
- Local HTTPS secures the browser-to-proxy connection; it does not independently verify gateway content or provide end-to-end TLS to TON sites.
- Content is retrieved in a trusted-gateway model. Independent content integrity verification is not implemented.
- Failed Web3 requests do not fall through to the ordinary fallback proxy. ENS CCIP Read is restricted to public HTTPS destinations.
- SNS V1, `.sol` compatibility, HTTP/3 (QUIC), UDP forwarding and WebSocket upgrades are not supported. Full DApp, wallet and Service Worker compatibility has not been established.

---

## 简体中文

**Fogmals DWeb Proxy（`dwebproxy`）** 是一个用 Go 编写的轻量、模块化的去中心化网络（DWeb）本地代理。它通过配置的 RPC 在本地执行 ENS、SNS 内容解析，借助内容网关获取网站内容，并将 TON 请求交给已有的 TON Proxy。

无需更换浏览器或修改系统 DNS，只需设置本地代理，即可访问支持的 Web3 域名，并在浏览器地址栏保留原始域名，例如 `https://example.eth/docs/`。

### 主要特性

- **Web3 多域名支持** — ENS（`.eth`）、SNS（`.sns`）和 TON（`.ton`）。
- **多种内容网络** — 支持 IPFS、IPNS、Arweave 和 Swarm，可灵活配置内容网关。
- **灵活的代理接入** — 支持 HTTP 或 SOCKS5 入口，以及 HTTP(S)、SOCKS5 下一跳。
- **本地 HTTPS** — 用户自行管理 CA，为 Web3 域名提供本地 TLS 和浏览器侧 HTTP/2，兼容 HTTP/1.1。
- **普通网站兼容** — 可通过 Fallback 代理访问普通 HTTP 网站，并透明转发普通 HTTPS 隧道，不解密其 TLS 流量。
- **可配置的解析与分流** — 支持 SNS 记录优先级、网关故障回退、解析缓存和程序出站代理；本地及内网地址自动绕过程序代理。

### 支持范围

| 域名 | 解析方式 | 内容获取 / 转发 |
| --- | --- | --- |
| `.eth` | ENS Universal Resolver、ENSIP-15、CCIP Read、`contenthash` | IPFS / IPNS / Arweave / Swarm |
| `.sns` | Solana RPC、SNS Records V2 | IPFS / IPNS / Arweave（优先级可配置） |
| `.ton` | 外部 TON Proxy | HTTP 转发 |
| 其他域名或 IP | 不执行链上解析 | 可选 Fallback 代理 |

所有分流规则均由程序内部执行，客户端只需配置一个本地代理入口。

### 快速开始

**环境要求：** 从源码构建需要 Go 1.27.3 或更高版本；访问相应网络还需可用的 RPC、内容网关或下一跳代理。本项目不内置这些外部服务。

在项目根目录执行：

```bash
go build -o dwebproxy ./cmd/dwebproxy
cp config.example.json config.json
./dwebproxy -config config.json -init-ca
./dwebproxy -config config.json
```

以上命令适用于 POSIX Shell。每套安装仅需初始化一次 CA，已有 CA 文件不会被覆盖。

Web3 HTTPS 默认开启。访问 Web3 HTTPS 网站前，请将 **`certs/ca.pem` 公共证书**导入浏览器或系统的受信任根证书库。切勿导入、分享或上传 `certs/ca-key.pem` 私钥。

将浏览器的 HTTP 和 HTTPS 目标均设置为使用手动 HTTP 代理 `127.0.0.1:18080`。从旧版本升级时，请关闭原有 PAC 自动代理配置。

随后即可访问已设置有效内容记录的 Web3 域名，也可以通过 curl 测试：

```bash
curl --noproxy '' -x http://127.0.0.1:18080 http://example.eth/
```

`example.eth` 仅为语法示例，不保证存在可访问的网站内容。

### 配置

参考 [`config.example.json`](config.example.json)，修改复制得到的 `config.json`。配置采用严格 JSON 格式，只需填写要覆盖的字段；修改后重启程序。

| 配置项 | 默认值 / 用途 |
| --- | --- |
| `listen` | `127.0.0.1:18080`，仅监听回环地址 |
| `listen_protocol` | `http`，可切换为 `socks5` |
| `ethereum_rpc`、`solana_rpc` | 公共 RPC，可替换为自选节点 |
| `record_priority` | ENS：ContentHash；SNS：IPFS → IPNS → Arweave |
| `ipfs_gateways` | `http://localhost:8080` |
| `arweave_gateways` | `http://localhost:1984` |
| `swarm_gateways` | `http://localhost:1633` |
| `ton_proxy` | 默认留空，需配置已有 TON Proxy 才能访问 `.ton` |
| `fallback_proxy` | 默认留空，用于普通网站的下一跳代理 |
| `program_proxy` | 默认关闭，用于 RPC、网关及下一跳等程序出站连接 |
| `https.enabled` | `true`，仅控制 Web3 本地 HTTPS |

IPFS/IPNS 强制使用**子域名网关**，网关须填写 DNS 主机名（如 `localhost`，而非 `127.0.0.1`）。使用 Kubo 时，可执行以下命令启用子域名网关，并重启 Kubo：

```bash
ipfs config --json Gateway.PublicGateways.localhost '{"Paths":["/ipfs","/ipns"],"UseSubdomains":true}'
```

Arweave 多文件网站需要支持 Path Manifest 的网关；Swarm 需要兼容 Bee 的内容网关。默认不启用公共内容网关回退。

如需 SOCKS5 入口，将 `listen_protocol` 设为 `socks5`，并在浏览器中启用代理端 DNS 解析（curl 使用 `socks5h://`）。TON 和 Fallback 下一跳的协议可独立选择 HTTP(S) 或 SOCKS5。

如果不希望初始化和信任本地 CA，可将 `https.enabled` 设为 `false`，使用 `http://` 访问 Web3 网站。普通 HTTPS 仍可通过已配置的 Fallback 代理透明转发。

常用命令：

```bash
./dwebproxy -print-config
./dwebproxy -config config.json -check
```

### 安全与使用边界

- ENS/SNS 内容访问仅支持 GET/HEAD；本项目不是钱包，也不是区块链节点。
- 本地 HTTPS 保护浏览器与本程序之间的连接，不代表内容已经独立验证，也不代表与 TON 网站建立端到端 TLS。
- 内容获取采用信任网关模式，暂未实现独立的内容完整性验证。
- Web3 域名解析或内容获取失败时，不会转入普通 Fallback；ENS CCIP Read 仅允许公网 HTTPS 目的地。
- 暂不支持 SNS V1、`.sol` 兼容解析、HTTP/3（QUIC）、UDP 转发和 WebSocket Upgrade；完整 DApp、钱包及 Service Worker 兼容性仍需验证。

---

## Development / 开发

```bash
gofmt -w cmd internal
go test -race ./...
go vet ./...
go build ./cmd/dwebproxy
```

Tests do not require live blockchain nodes. Real browser and gateway integration should be verified in the deployment environment.

自动化测试不依赖真实链节点；实际浏览器及网关的兼容性仍需在部署环境中验证。

## Protocol references / 协议参考

- [ENS Universal Resolver](https://docs.ens.domains/resolvers/universal/) · [ENSIP-7](https://docs.ens.domains/ensip/7/)
- [SNS SDK](https://github.com/SolanaNameService/sns-sdk) · [SNS-IP-3](https://github.com/SolanaNameService/sns-ip/blob/master/proposals/sns-ip-3.md)
- [IPFS Subdomain Gateway](https://specs.ipfs.tech/http-gateways/subdomain-gateway/)
- [Arweave Path Manifests](https://github.com/ArweaveTeam/arweave/wiki/Path-Manifests)
- [Bee manifests](https://docs.ethswarm.org/docs/develop/tools-and-features/manifests/)
- [TON Proxy](https://docs.ton.org/foundations/web3/ton-proxy)

## Contributing / 参与贡献

This project is under active development. Bug reports, suggestions and discussions are welcome via GitHub Issues!

本项目正在持续开发中，欢迎通过 GitHub Issues 反馈问题、提出建议或参与讨论！
