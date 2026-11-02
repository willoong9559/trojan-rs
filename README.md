# Trojan-RS

Rust 实现的 Trojan 服务端，支持 TCP、WebSocket、gRPC 与 REALITY。

## 构建与运行

```bash
cargo build --release
./target/release/trojan-rs -c server.toml
```

运行配置使用 TOML。生成完整示例：

```bash
./target/release/trojan-rs --generate-config server.toml
```

常用命令行参数仅用于选择配置、日志与生成 REALITY 密钥：

```text
-c, --config-file <FILE>
--generate-config <FILE>
--generate-reality-keypair
--log-level <trace|debug|info|warn|error>
```

## 配置

`[server]` 定义共享的资源限制和 gRPC 限制。每个 `[[inbounds]]` 必须设置自己的 `password`。`listen` 是 Socket 地址数组，因此 `0.0.0.0:PORT` 与 `[::]:PORT` 可以同时监听同一端口的 IPv4 和 IPv6。

```toml
[server]
# 所有入口共享这些限制。
max_connections = 1024
max_tls_handshakes = 64
max_connections_per_ip = 32

# 所有 gRPC 入口共享这些限制。
grpc_max_concurrent_streams = 128
grpc_max_read_buffer_bytes = 262144
grpc_max_message_bytes = 16384
grpc_max_send_queue_bytes = 131072

# 1. 原生 Trojan TCP over TLS
[[inbounds]]
tag = "trojan-tcp"
listen = ["0.0.0.0:443", "[::]:443"]
transport = "tcp"
password = "tcp-strong-password"
tls = { cert = "/etc/trojan-rs/cert.pem", key = "/etc/trojan-rs/key.pem" }

# 2. Trojan WebSocket over TLS
[[inbounds]]
tag = "trojan-ws"
listen = ["0.0.0.0:8443", "[::]:8443"]
transport = "websocket"
password = "ws-strong-password"
ws_host = "cdn.example.com"
ws_path = "/trojan"
tls = { cert = "/etc/trojan-rs/cert.pem", key = "/etc/trojan-rs/key.pem" }

# 3. Trojan gRPC over TLS
[[inbounds]]
tag = "trojan-grpc"
listen = ["0.0.0.0:9443", "[::]:9443"]
transport = "grpc"
grpc_service_name = "GunService"
password = "a-separate-strong-password"
tls = { cert = "/etc/trojan-rs/cert.pem", key = "/etc/trojan-rs/key.pem" }

# 4. Trojan gRPC over REALITY
[[inbounds]]
tag = "trojan-reality-grpc"
listen = ["0.0.0.0:10443", "[::]:10443"]
transport = "grpc"
grpc_service_name = "RealityService"
password = "reality-strong-password"
reality = { dest = "www.example.com:443", private_key = "base64url-x25519-private-key", short_ids = ["0123456789abcdef"], max_time_diff_ms = 60000 }

# 5. Unix Domain Socket（仅本机进程可连接）
[[inbounds]]
tag = "trojan-uds"
unix_path = "/run/trojan-rs/trojan.sock"
transport = "websocket"
password = "uds-strong-password"
ws_path = "/trojan-uds"

[log]
level = "info"
```

`transport` 可取：`tcp`、`websocket`、`grpc`。`ws_host`、`ws_path` 只用于 WebSocket；`grpc_service_name` 只用于 gRPC。`unix_path` 为 Unix Domain Socket 路径；它可以与 `listen` 同时配置，但不能用于 REALITY。

REALITY 不能和同一入口的 `tls` 同时设置。

## REALITY 密钥

生成 X25519 密钥对：

```bash
./target/release/trojan-rs --generate-reality-keypair
```

## 证书

为 TLS、WebSocket 或 gRPC 配置 PEM 证书与私钥路径：`tls = { cert = "...", key = "..." }`。证书更新后重启 Trojan-RS 以载入新文件。

## 协议支持

- TCP CONNECT
- UDP ASSOCIATE（UDP over TCP）
- IPv4、IPv6 与域名目标
- TCP、WebSocket、gRPC、REALITY 入口

## 许可证

查看 [LICENSE](LICENSE)。
