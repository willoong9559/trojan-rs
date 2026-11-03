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

`[server]` 定义共享的资源限制、gRPC 限制和可选的内置 ACME 设置。每个 `[[inbounds]]` 必须设置自己的 `protocol` 和 `password`。`trojan` 的 `password` 是普通密码，`vless` 的 `password` 必须是 UUID。`listen` 是 Socket 地址数组，因此 `0.0.0.0:PORT` 与 `[::]:PORT` 可以同时监听同一端口的 IPv4 和 IPv6。

```toml
[server]
# 所有入口共享这些限制。
max_connections = 1024
# 同时进行中的 TLS/REALITY 握手数，并非 TLS 连接总数。
max_tls_handshakes = 64
# 注意：若使用 TCP 或 WebSocket，客户端可能并发建立多个连接；请考虑提高到 128 及以上。
max_connections_per_ip = 32

# 所有 gRPC 入口共享这些限制。
grpc_max_concurrent_streams = 128
grpc_max_read_buffer_bytes = 262144
grpc_max_message_bytes = 16384
grpc_max_send_queue_bytes = 131072

# 内置 ACME：只由 acme = true 的入口使用。
acme = { domain = "tunnel.example.com", email = "admin@example.com", cache_dir = "/var/lib/trojan-rs/acme", staging = false }

# 1. 原生 Trojan TCP over 内置 ACME TLS
[[inbounds]]
tag = "trojan-tcp"
listen = ["0.0.0.0:443", "[::]:443"]
transport = "tcp"
protocol = "trojan"
password = "tcp-strong-password"
acme = true

# 2. Trojan WebSocket over 内置 ACME TLS
[[inbounds]]
tag = "trojan-ws"
listen = ["0.0.0.0:8443", "[::]:8443"]
transport = "websocket"
protocol = "trojan"
password = "ws-strong-password"
ws_host = "tunnel.example.com"
ws_path = "/trojan"
acme = true

# 3. VLESS gRPC over TLS
[[inbounds]]
tag = "vless-grpc"
listen = ["0.0.0.0:9443", "[::]:9443"]
transport = "grpc"
grpc_service_name = "GunService"
protocol = "vless"
password = "01234567-89ab-cdef-0123-456789abcdef"
tls = { cert = "/etc/trojan-rs/cert.pem", key = "/etc/trojan-rs/key.pem" }

# 4. Trojan gRPC over REALITY
[[inbounds]]
tag = "trojan-reality-grpc"
listen = ["0.0.0.0:10443", "[::]:10443"]
transport = "grpc"
protocol = "trojan"
grpc_service_name = "RealityService"
password = "reality-strong-password"
reality = { dest = "www.example.com:443", private_key = "base64url-x25519-private-key", short_ids = ["0123456789abcdef"], max_time_diff_ms = 60000 }

# 5. Unix Domain Socket（仅本机进程可连接）
[[inbounds]]
tag = "trojan-uds"
unix_path = "/run/trojan-rs/trojan.sock"
transport = "websocket"
protocol = "trojan"
password = "uds-strong-password"
ws_path = "/trojan-uds"

[log]
level = "info"
```

`protocol` 必须为 `trojan` 或 `vless`；`transport` 可取：`tcp`、`websocket`、`grpc`。`ws_host`、`ws_path` 只用于 WebSocket；`grpc_service_name` 只用于 gRPC。`unix_path` 为 Unix Domain Socket 路径；它可以与 `listen` 同时配置，但不能用于 REALITY。

VLESS 支持 TCP 与标准 UDP。VLESS UDP 使用请求头中的单一目标地址和 `u16` 长度分包，不支持 XUDP、Vision Flow 或 Full Cone。

入口只能在 `tls`、`acme = true`、`reality` 三种 TLS 方式中选择一种。`acme = true` 必须配合 `[server]` 中的 `acme`；所有选用 ACME 的入口共享同一账户和证书。ACME 只能用于 TCP 监听，不能用于 `unix_path`。

## REALITY 密钥

生成 X25519 密钥对：

```bash
./target/release/trojan-rs --generate-reality-keypair
```

## 证书

TLS、WebSocket 与 gRPC 接受 PEM 或 DER 编码的 X.509 证书和 PKCS#8、PKCS#1、SEC1 私钥；格式会自动识别。PEM 证书文件可直接包含完整链。若使用单独的中间证书文件（尤其是 DER），配置 `cert_chain`：

```toml
tls = { cert = "/etc/trojan-rs/cert.der", key = "/etc/trojan-rs/key.der", cert_chain = ["/etc/trojan-rs/intermediate.der"] }
```

静态证书更新后重启 Trojan-RS 以载入新文件。不支持 `.p12/.pfx`、JKS 或加密私钥。

## ACME

内置 ACME 使用 Let's Encrypt 的 TLS-ALPN-01 挑战，会自动创建账户、签发、续期并在进程内更新证书，不依赖 acme.sh。`domain` 必须解析到本机；该域名的 TCP `443` 必须由设置了 `acme = true` 的入口监听并可从公网访问。`cache_dir` 必须持久化保存，首次验证时可将 `staging = true`，确认成功后改回 `false` 并重启服务以签发正式证书。

## 协议支持

- Trojan 与 VLESS
- TCP CONNECT
- Trojan UDP ASSOCIATE 与标准 VLESS UDP（均为 UDP over TCP）
- IPv4、IPv6 与域名目标
- TCP、WebSocket、gRPC、REALITY 入口

## 许可证

查看 [LICENSE](LICENSE)。
