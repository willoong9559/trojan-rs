# Trojan WS Server

A simple **Trojan WebSocket (WS)** server configuration using Rust.

This server allows you to run a Trojan WS server with configurable host, port, and password via command line arguments.  
It also supports **optional TLS encryption**, allowing you to serve secure WebSocket connections over `wss://`.

---

## Command Line Arguments

The server uses [**clap**](https://crates.io/crates/clap) to parse command line arguments.  
The available options are:

| Argument         | Description                     | Type   | Default Value   |
|------------------|----------------------------------|--------|----------------|
| `--host`         | Host address                     | String | `127.0.0.1`    |
| `--port`         | Port number                      | String | `35537`        |
| `--password`     | Password for server               | String | *(required)*   |
| `--cert <FILE>`  | TLS certificate file path (PEM)   | String | *(optional)*   |
| `--key <FILE>`   | TLS private key file path (PEM)   | String | *(optional)*   |

> **Note:**  
> If both `--cert` and `--key` are provided, the server automatically enables **TLS mode** and listens for secure WebSocket (`wss://`) connections.  
> If they are omitted, the server runs in plain WS mode (`ws://`).

---

## Example Usage

### Run without TLS
Run the server with the default host and port, specifying only a password:

```bash
cargo run -- --password mysecretpassword
