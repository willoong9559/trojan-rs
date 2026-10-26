# Trojan-RS

一个用 Rust 实现的 Trojan 代理服务器，支持多种传输模式。

## 特性

- 🔒 **TLS 加密**：支持可选的 TLS/SSL 加密传输
- 🫥 **REALITY**：可选替代 TLS；认证失败的客户端会被透明转发至配置的覆盖站
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
| `--enable-reality` | 启用 REALITY，替代 TLS | Flag | `false` | 否 |
| `--reality-dest <HOST:PORT>` | REALITY 覆盖站（必须是 DNS 主机名） | String | - | 启用时必需 |
| `--reality-private-key <KEY>` | REALITY X25519 私钥（base64url，无填充） | String | - | 启用时必需 |
| `--reality-short-id <HEX>` | 接受的 short ID（可重复，0–16 位十六进制） | String | - | 启用时必需 |
| `--reality-max-time-diff-ms <MS>` | 可选客户端时钟最大偏差 | Integer | - | 否 |
| `--generate-reality-keypair` | 生成 REALITY X25519 密钥对后退出 | Flag | `false` | 否 |
| `--unix-path <PATH>` | Unix Domain Socket 监听路径 (仅 Unix 平台) | String | - | 否 |
| `--enable-ws` | 启用 WebSocket 模式 | Flag | 禁用 | 否 |
| `--enable-grpc` | 启用 gRPC 模式 | Flag | 禁用 | 否 |
| `--ws-host <HOST>` | WebSocket Host 头 | String | - | 否 |
| `--ws-path <PATH>` | WebSocket 请求路径 | String | - | 否 |
| `--grpc-service-name <NAME>` | gRPC service name | String | - | 否 |
| `--grpc-max-concurrent-streams <N>` | 单个 HTTP/2 连接允许的最大 gRPC stream 数 | Integer | `128` | 否 |
| `--grpc-max-read-buffer-bytes <N>` | 单个 gRPC stream 的最大请求缓冲字节数 | Integer | `262144` | 否 |
| `--grpc-max-message-bytes <N>` | 单条 gRPC 消息的最大负载字节数 | Integer | `16384` | 否 |
| `--grpc-max-send-queue-bytes <N>` | 单个 gRPC stream 的最大响应队列字节数 | Integer | `131072` | 否 |
| `--max-connections <N>` | 最大存活连接数（包含 TLS 握手中连接） | Integer | `1024` | 否 |
| `--max-tls-handshakes <N>` | 最大并发 TLS 握手数 | Integer | `64` | 否 |
| `--max-connections-per-ip <N>` | 单个 IP 最大存活 TCP 连接数 | Integer | `32` | 否 |
| `--acme-domain <DOMAIN>` | 通过 TLS-ALPN-01 自动签发证书的域名 | String | - | 否 |
| `--acme-email <EMAIL>` | Let's Encrypt 账户联系邮箱；须与 `--acme-domain` 同时配置 | String | - | 否 |
| `--acme-cache-dir <PATH>` | ACME 账户和证书缓存目录 | String | `/var/lib/trojan-rs/acme` | 否 |
| `--acme-staging` | 使用 Let's Encrypt 测试环境 | Flag | `false` | 否 |
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
> - REALITY 与静态 TLS 证书、ACME 互斥。`reality_dest` 是对未认证探测流量的回落目标，应选择支持 TLS 1.3 的可信 HTTPS 主机。

生成 REALITY 密钥对无需安装 Xray：

```bash
trojan-rs --generate-reality-keypair
```

将输出的 `Private key` 写入服务端 `private_key`，将 `Public key` 写入客户端 Reality 配置。short ID 可用 `openssl rand -hex 8` 生成。
> - 单个 stream 的发送窗口连续 30 秒未恢复时会被重置，客户端应在连接或 stream 错误后重建隧道并持续读取响应数据以更新 HTTP/2 流控窗口
> - ACME 使用 TLS-ALPN-01，因此域名必须解析到本机且 TCP 443 必须由 Trojan-RS 独占；`acme_domain`/`acme_email` 与静态证书配置互斥

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
grpc_max_concurrent_streams = 128
grpc_max_read_buffer_bytes = 262144
grpc_max_message_bytes = 16384
grpc_max_send_queue_bytes = 131072
max_connections = 1024
max_tls_handshakes = 64
max_connections_per_ip = 32
# 配置以下两项后，Trojan-RS 会自动签发、续期并热加载 Let's Encrypt 证书。
acme_domain = "tunnel.example.com"
acme_email = "admin@example.com"
acme_cache_dir = "/var/lib/trojan-rs/acme"
# 首次测试时建议设为 true，避免消耗生产环境签发额度。
acme_staging = false
# unix_path = "/var/run/trojan-rs.sock"

[tls]
# 静态证书模式；与 ACME 配置互斥。
cert = "/path/to/cert.pem"
key = "/path/to/key.pem"

# REALITY 模式：启用后不应配置 [tls] 或 ACME。
# private_key 为 X25519 私钥；客户端使用其对应 public key。
# 可配置多个 short_ids，以便轮换。
# [reality]
# dest = "www.example.com:443"
# private_key = "base64url-x25519-private-key"
# short_ids = ["0123456789abcdef"]
# max_time_diff_ms = 60000

[log]
level = "info"
```

### ACME + gRPC 一键部署

[`scripts/install_acme_grpc.sh`](scripts/install_acme_grpc.sh) 会通过 GitHub Releases API 下载最新的 `x86_64-unknown-linux-musl` 构建，以 systemd 直接运行 Trojan-RS，并把域名、邮箱和 ACME 缓存目录写入 Trojan-RS 配置。证书签发与续期使用内置 TLS-ALPN-01，不需要 Nginx、acme.sh 或 TCP 80。

使用前请将域名的 A/AAAA 记录指向服务器，放行 TCP 443，并确保端口未被其他服务占用。脚本需要 systemd、x86_64 Linux，且会安装 curl、unzip、jq 与 ca-certificates：

```bash
curl -fsSLO https://raw.githubusercontent.com/willoong9559/trojan-rs/main/scripts/install_acme_grpc.sh
chmod +x install_acme_grpc.sh
sudo ./install_acme_grpc.sh \
  --domain example.com \
  --email admin@example.com \
  --service-name GunService \
  --password 'trojan-rs-password'
```

若不使用 `--password`，脚本会通过 `read -s` 隐藏式读取密码。脚本每次运行都会获取最新 Release，因此可用同一命令升级二进制。首次测试可加 `--acme-staging` 使用 Let's Encrypt 测试环境，确认无误后移除该参数重新运行。ACME 状态保存在 `/var/lib/trojan-rs/acme`，重新运行脚本不会重复创建账户。

#### 支持的 Linux 发行版

脚本会根据包管理器安装依赖，并通过 systemd 创建 `trojan-rs.service`。以下是受支持的系统系列：

- Debian 11+、Ubuntu 20.04+（`apt-get`）
- RHEL 8+、CentOS Stream、Rocky Linux、AlmaLinux、Fedora、Amazon Linux（`dnf` 或 `yum`）
- openSUSE Leap/Tumbleweed、SUSE Linux Enterprise（`zypper`）
- Arch Linux（`pacman`）

不支持默认使用 OpenRC 的 Alpine Linux；也不支持非 x86_64 架构，因为当前自动下载的是 `rust-build-x86_64-unknown-linux-musl.zip`。其他发行版可以在已手动安装 curl、unzip、jq、ca-certificates 和 systemd 的前提下尝试运行，但不属于脚本的兼容范围。

## 协议支持

- ✅ TCP 代理（CONNECT 命令）
- ✅ UDP 代理（UDP ASSOCIATE 命令，UDP over TCP）
- ✅ IPv4 和 IPv6 地址
- ✅ 域名解析

## 许可证

查看 [LICENSE](LICENSE) 文件了解详情。
