# Trojan-RS

一个用 Rust 实现的 Trojan 代理服务器，支持多种传输模式。

## 特性

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
git clone https://github.com/willoong9559/trojan-rs.git
cd trojan-rs

# 构建发布版本
cargo build --release

# 可执行文件位于 target/release/trojan-rs
```

### 针对当前 CPU 编译

在支持的环境下，你可以使用 `target-cpu=native` 等选项为当前机器 CPU 做更激进的优化（适合自行部署的服务器场景）：

```bash
# 使用 RUSTFLAGS 为当前 CPU 优化并开启较高优化级别
RUSTFLAGS="-C target-cpu=native -C opt-level=3" cargo build --release

# 或使用 cargo rustc 显式传递编译参数
cargo rustc --release -- -C target-cpu=native -C opt-level=3
```

> **提示**：
> - 这会使生成的二进制使用当前 CPU 的指令集，可能无法在较老或不同指令集的 CPU 上运行。
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
| `--unix-path <PATH>` | Unix Domain Socket 监听路径 (仅 Unix 平台) | String | - | 否 |
| `--enable-ws` | 启用 WebSocket 模式 | Flag | 禁用 | 否 |
| `--enable-grpc` | 启用 gRPC 模式 | Flag | 禁用 | 否 |
| `--ws-host <HOST>` | WebSocket Host 头 | String | - | 否 |
| `--ws-path <PATH>` | WebSocket 请求路径 | String | - | 否 |
| `--grpc-service-name <NAME>` | gRPC service name | String | - | 否 |
| `-c, --config-file <FILE>` | 从 TOML 文件加载配置 | String | - | 否 |
| `--generate-config <FILE>` | 生成示例配置文件 | String | - | 否 |
| `--log-level <LEVEL>` | 日志级别 (trace/debug/info/warn/error) | String | `info` | 否 |
| `-h, --help` | 显示帮助信息 | - | - | - |
| `-V, --version` | 显示版本信息 | - | - | - |

> **注意**：
> - 如果同时提供 `--cert` 和 `--key`，服务器将自动启用 TLS 模式
> - `--enable-ws` 和 `--enable-grpc` 不能同时启用
> - 命令行参数会覆盖配置文件中的对应设置
> - 配置了 `ws_host` 后，WebSocket 模式会校验 `Host` 头
> - 配置了 `ws_path` 后，WebSocket 模式会校验请求路径
> - 配置了 `grpc_service_name` 后，gRPC 模式会严格校验 service name
> - TLS 证书和私钥必须为 PEM 格式（rustls 仅支持 PEM 格式）
> - 单个 stream 的发送窗口连续 30 秒未恢复时会被重置，客户端应在连接或 stream 错误后重建隧道并持续读取响应数据以更新 HTTP/2 流控窗口

#### 配置文件示例

编辑生成的 `server.toml` 文件：

```toml
[server]
host = "0.0.0.0"
port = "443"
password = "password"
enable_udp = true
enable_ws = false
enable_grpc = true
ws_host = "cdn.example.com"
ws_path = "/ws"
grpc_service_name = "GunService"
# unix_path = "/var/run/trojan-rs.sock"

[tls]
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"

[log]
level = "info"
```

### Nginx + gRPC + UDS 一键部署

[`scripts/install_nginx_grpc.sh`](scripts/install_nginx_grpc.sh) 会通过 GitHub Releases API 下载最新的 `x86_64-unknown-linux-musl` 构建，使用 systemd 将 Trojan-RS 运行在 UDS 上，并生成 Nginx gRPC 虚拟主机配置。它会用 acme.sh 申请 Let's Encrypt ECDSA 证书，并为之后的自动续期设置 Nginx reload hook。

使用前请将域名的 A/AAAA 记录指向服务器，并在防火墙放行 TCP 80/443。脚本目前需要 systemd、x86_64 Linux，且会安装 Nginx、curl、unzip、jq 与 acme.sh：

```bash
curl -fsSLO https://raw.githubusercontent.com/willoong9559/trojan-rs/main/scripts/install_nginx_grpc.sh
chmod +x install_nginx_grpc.sh
sudo ./install_nginx_grpc.sh \
  --domain example.com \
  --email admin@example.com \
  --service-name GunService \
  --password 'trojan-rs-password'
```

若不使用 `--password`，脚本会通过 `read -s` 隐藏式读取密码。脚本每次运行都会获取最新 Release，因此可用同一命令升级二进制。Nginx 的受管配置默认写入 `/etc/nginx/conf.d/trojan-rs.conf`；如果已有同域名的 `server` 块，请先迁移或移除它，以避免虚拟主机冲突。

#### 支持的 Linux 发行版

脚本会根据包管理器安装依赖，并通过 systemd 创建 `trojan-rs.service`。以下是受支持的系统系列：

- Debian 11+、Ubuntu 20.04+（`apt-get`）
- RHEL 8+、CentOS Stream、Rocky Linux、AlmaLinux、Fedora、Amazon Linux（`dnf` 或 `yum`）
- openSUSE Leap/Tumbleweed、SUSE Linux Enterprise（`zypper`）
- Arch Linux（`pacman`）

不支持默认使用 OpenRC 的 Alpine Linux；也不支持非 x86_64 架构，因为当前自动下载的是 `rust-build-x86_64-unknown-linux-musl.zip`。其他发行版可以在已手动安装 Nginx、curl、unzip、jq、ca-certificates 和 systemd 的前提下尝试运行，但不属于脚本的兼容范围。

## 协议支持

- ✅ TCP 代理（CONNECT 命令）
- ✅ UDP 代理（UDP ASSOCIATE 命令，UDP over TCP）
- ✅ IPv4 和 IPv6 地址
- ✅ 域名解析

## 许可证

查看 [LICENSE](LICENSE) 文件了解详情。
