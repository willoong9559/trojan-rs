# Trojan WS 服务端

一个使用 Rust 编写的 Trojan 服务端，实现 Trojan 协议在 **WebSocket** 与 **TCP+HTTP 伪装** 两种传输方式下的转发能力，可选启用 TLS 加密。

## 功能特性

- 基于 `tokio` 的异步高并发处理。
- 支持 TCP CONNECT 与 UDP ASSOCIATE 双模式转发。
- 可选加载 TLS 证书/私钥，开启 `wss://` 加密传输。
- **全中文命令行参数与运行日志**，部署体验更友好。
- 新增 `-q/--quiet` 静默模式，便于在自动化部署时关闭控制台输出。
- 新增 `--network` 与 `--tcp-header` 参数，兼容 Trojan `network="tcp"` + `header="http"` 的传输配置。

## 快速开始

### 安装依赖

```bash
cargo fetch
```

### 运行示例

```bash
# 使用默认监听地址与端口，指定密码即可启动（WebSocket 模式）
cargo run -- --password 我的超级密码

# 启用 TLS，并加载证书与私钥
cargo run -- --password 我的超级密码 --cert /path/to/cert.pem --key /path/to/key.pem

# 静默模式启动（仅保留必要的错误输出）
cargo run -- --password 我的超级密码 --quiet

# 切换为 TCP + HTTP 伪装头部（兼容 Xray Trojan 配置）
cargo run -- --password 我的超级密码 --network tcp --tcp-header http
```

## 命令行参数

| 参数                 | 说明                                      | 类型   | 默认值      |
|----------------------|-------------------------------------------|--------|-------------|
| `--host`             | 监听地址                                  | 字符串 | `127.0.0.1` |
| `--port`             | 监听端口                                  | 字符串 | `35537`     |
| `--password`         | 服务密码（必填）                          | 字符串 | 无          |
| `--cert <FILE>`      | TLS 证书文件（PEM 格式，可选）            | 字符串 | 无          |
| `--key <FILE>`       | TLS 私钥文件（PEM 格式，可选）            | 字符串 | 无          |
| `-q`, `--quiet`      | 静默模式，关闭控制台输出                  | 布尔值 | `false`     |
| `--network`          | 传输方式：`websocket` 或 `tcp`            | 字符串 | `websocket` |
| `--tcp-header`       | TCP 伪装头类型：`none` 或 `http`（仅 TCP） | 字符串 | `none`      |

> **提示**：`--cert` 与 `--key` 必须同时提供，缺一则视为无效，会提示错误。

## 静态编译

为便于跨平台部署，可使用 `cross` 进行静态编译（以 Linux musl 版本为例）：

```bash
cargo install cross
cross build --release --target x86_64-unknown-linux-musl
```

构建完成后，静态链接的可执行文件位于 `target/x86_64-unknown-linux-musl/release/trojan-rs`。

## GitHub Actions 工作流

项目内置 `Build Binaries` 工作流，可在推送代码或发布 Tag 时自动构建多平台二进制文件（含 musl 静态编译版本），并打包上传构建产物，方便快速分发。

## 许可证

本项目遵循 MIT 许可证发布，详情请参阅仓库中的 `LICENSE` 文件。
