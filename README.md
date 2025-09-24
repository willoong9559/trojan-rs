# Trojan WS Server

A simple Trojan WebSocket (WS) server configuration using Rust.

This server allows you to run a Trojan WS server with configurable host, port, and password via command line arguments.

## Command Line Arguments

The server uses [clap](https://crates.io/crates/clap) to parse command line arguments. The available options are:

| Argument       | Description        | Type   | Default Value   |
|----------------|------------------|--------|----------------|
| `--host`       | Host address       | String | `127.0.0.1`    |
| `--port`       | Port number        | String | `35537`        |
| `--password`   | Password for server | String | (required)     |

### Example Usage

Run the server with default host and port, specifying a password:

```bash
cargo run --password mysecretpassword
