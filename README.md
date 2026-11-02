<h1 align="center">Fogmals DWeb Proxy</h1>

<p align="center">
  让 Web3 域名走进熟悉的浏览器。
</p>

<p align="center">
  By Gakmots & Codex
</p>

<p align="center">
    
<img src="https://img.shields.io/badge/version-0.1.0-2563eb?style=flat-square" alt="Version 0.1.0">
    
<img src="https://img.shields.io/badge/Go-1.27.3%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.27.3+">
    
</p>



<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#配置">配置</a> ·
  <a href="#特别说明">特别说明</a> ·
  <a href="CHANGELOG.md">更新记录</a>
</p>

**Fogmals Dweb Proxy** 是一个用 Go 编写的去中心化网站（DWeb）本地内容代理。可通过搭配不同的本地内容网关和代理实现无缝的 DWeb 浏览器体验。

## 特性

- **Web3多域名支持** — 已实现.eth、.sns、.bnb、.ton和.i2p域名支持
- **沿用 Web 协议** — 支持常规 HTTP 方法、认证与 Cookie、流式上传、SSE 和 HTTP/1.1 WebSocket。
- **本地 HTTPS** — 为支持的专用域名启用本地 TLS，证书由用户自行初始化并信任。**多类型内容支持** — 可选的IPFS/IPNS、Arweave内容支持
- **模块化设计** — 灵活与各类去中心化网络（DWeb）的网关和代理工具搭配使用，做好自己的事情。



本项目正在密集开发中，现阶段的功能非常不稳定，请谨慎使用
