# Trojan-RS

一个用 Rust 实现的高性能 Trojan 代理服务器，支持多种传输模式。

## 特性

- 🚀 **高性能**：基于 Rust 和 Tokio 异步运行时，提供出色的并发性能
- 🔒 **TLS 加密**：支持可选的 TLS/SSL 加密传输
- 🌐 **多种传输模式**：
  - TCP 模式（原生 Trojan 协议）
  - WebSocket 模式（支持 WebSocket over TLS）
  - gRPC 模式（兼容 v2ray， 支持多路复用）
- 📦 **UDP 代理**：完整支持 UDP 流量转发

## 安装

### 从源码构建

```bash
# 克隆仓库
git clone <repo_url>
cd trojan-rs

# 构建发布版本
cargo build --release

# 可执行文件位于 target/release/trojan-rs
```

### 针对 CPU 的优化编译

在支持的环境下，你可以使用 `target-cpu=native` 等选项为当前机器 CPU 做更激进的优化（适合自行部署的服务器场景）：

```bash
# 使用 RUSTFLAGS 为当前 CPU 优化并开启较高优化级别
RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo build --release

# 或使用 cargo rustc 显式传递编译参数
cargo rustc --release -- -C target-cpu=native -C opt-level=3
```

> **提示**：
> - 这些优化通常会提升性能，但生成的二进制可能无法在较老或不同指令集的 CPU 上运行。
> - 如果需要在多种不同 CPU 上分发二进制，请继续使用默认的 `cargo build --release`。

## 使用方法

### 命令行参数

| 参数 | 描述 | 类型 | 默认值 | 必需 |
|------|------|------|--------|------|
| `--host <HOST>` | 服务器监听地址 | String | `127.0.0.1` | 否 |
| `--port <PORT>` | 服务器监听端口 | String | `35537` | 否 |
| `--password <PASSWORD>` | 服务器密码 | String | - | **是** |
| `--cert <FILE>` | TLS 证书文件路径 (PEM 格式) | String | - | 否 |
| `--key <FILE>` | TLS 私钥文件路径 (PEM 格式) | String | - | 否 |
| `--enable-ws` | 启用 WebSocket 模式 | Flag | 禁用 | 否 |
| `--enable-grpc` | 启用 gRPC 模式 | Flag | 禁用 | 否 |
| `-c, --config-file <FILE>` | 从 TOML 文件加载配置 | String | - | 否 |
| `--generate-config <FILE>` | 生成示例配置文件 | String | - | 否 |
| `--log-level <LEVEL>` | 日志级别 (trace/debug/info/warn/error) | String | `info` | 否 |
| `-h, --help` | 显示帮助信息 | - | - | - |
| `-V, --version` | 显示版本信息 | - | - | - |

> **注意**：
> - 如果同时提供 `--cert` 和 `--key`，服务器将自动启用 TLS 模式
> - `--enable-ws` 和 `--enable-grpc` 不能同时启用
> - 命令行参数会覆盖配置文件中的对应设置
> - WebSocket 模式不验证 host 和 path
> - gRPC 模式不验证服务名称
> - TLS 证书和私钥必须为 PEM 格式（rustls 仅支持 PEM 格式）

#### 配置文件示例

编辑生成的 `server.toml` 文件：

```toml
[server]
host = "0.0.0.0"
port = "443"
password = "mysecretpassword"
enable_ws = true
enable_grpc = false

[tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"

[log]
level = "info"
```

## 协议支持

- ✅ TCP 代理（CONNECT 命令）
- ✅ UDP 代理（UDP ASSOCIATE 命令，UDP over TCP）
- ✅ IPv4 和 IPv6 地址
- ✅ 域名解析

## 许可证

查看 [LICENSE](LICENSE) 文件了解详情。
