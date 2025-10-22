# Trojan WS Server

A simple **Trojan** server implemented in **Rust**.  
This server allows you to run a Trojan server with configurable host, port, and password via **command-line arguments**.  
It also supports **optional TLS encryption** and **WebSocket mode**, allowing you to serve secure or plain WebSocket connections over `wss://` or `ws://`.

---

## Command-Line Arguments

The server uses [**clap**](https://crates.io/crates/clap) to parse command-line arguments.  
Available options:

| Argument                     | Description                               | Type    | Default Value   |
|-------------------------------|-------------------------------------------|---------|----------------|
| `--host <HOST>`              | Host address                               | String  | `127.0.0.1`    |
| `--port <PORT>`              | Port number                                | String  | `35537`        |
| `--password <PASSWORD>`      | Password for the server                    | String  | *(required)*   |
| `--cert <FILE>`              | TLS certificate file path (PEM)           | String  | *(optional)*   |
| `--key <FILE>`               | TLS private key file path (PEM)           | String  | *(optional)*   |
| `--enable-ws`                | Enable WebSocket mode (TCP/TLS)           | Flag    | disabled       |
| `-c, --config-file <FILE>`   | Load configuration from TOML file         | String  | *(optional)*   |
| `--generate-config <FILE>`   | Generate example TOML configuration file | String  | *(optional)*   |
| `-h, --help`                 | Print help                                 | -       | -              |
| `-V, --version`              | Print version                              | -       | -              |

> **Note:**  
> - If both `--cert` and `--key` are provided, the server automatically enables **TLS mode** (`wss://`).  
> - If `--enable-ws` is set, the server will accept WebSocket connections; otherwise it runs in plain TCP mode.  
> - CLI arguments override configuration file values.

---

## Example Usage

### Run without TLS

Run the server with default host and port, specifying only a password:

```bash
cargo run -- --password mysecretpassword
```
### Run with TLS
```bash
cargo run -- --host 0.0.0.0 --port 443 \
           --password mysecretpassword \
           --cert ./cert.pem --key ./key.pem
```
### Run using a Configuration File
#### Generate an example TOML config:
```bash
cargo run -- --generate-config server.toml
```
#### Edit server.toml to set your password and TLS paths:
```toml
[server]
host = "0.0.0.0"
port = "443"
password = "mysecretpassword"
enable_ws = true

[tls]
cert = "/path/to/cert.pem"
key  = "/path/to/key.pem"
```
#### Start the server using the config file:
```bash
cargo run -- --config-file server.toml
```
#### You can still override values via CLI:
```bash
cargo run -- --config-file server.toml --port 8443
```

## Installation
### Build and run locally:
```bash
git clone <repo_url>
cd trojan-rs
cargo build --release
./target/release/trojan-rs --help
```
