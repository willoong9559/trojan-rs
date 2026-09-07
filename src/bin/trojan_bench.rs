//! End-to-end benchmark client for a native Trojan TCP inbound.
//!
//! It starts a local echo target, opens a configurable number of Trojan
//! tunnels to the server under test, and reports aggregate application
//! throughput plus a one-byte round-trip latency sample.

use sha2::{Digest, Sha224};
use std::env;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify};

const DEFAULT_PROXY_ADDR: &str = "127.0.0.1:18443";
const DEFAULT_ECHO_ADDR: &str = "127.0.0.1:19000";
const DEFAULT_PASSWORD: &str = "trojan-rs-benchmark";
const DEFAULT_CONNECTIONS: usize = 32;
const DEFAULT_BYTES_PER_CONNECTION: usize = 64 * 1024 * 1024;
const DEFAULT_PING_ROUNDS: usize = 1_000;
const IO_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Debug)]
struct Config {
    proxy_addr: SocketAddr,
    socks_addr: Option<SocketAddr>,
    echo_addr: SocketAddr,
    password: String,
    connections: usize,
    bytes_per_connection: usize,
    ping_rounds: usize,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut proxy_addr: SocketAddr = DEFAULT_PROXY_ADDR.parse().unwrap();
        let mut socks_addr = None;
        let mut echo_addr: SocketAddr = DEFAULT_ECHO_ADDR.parse().unwrap();
        let mut password = DEFAULT_PASSWORD.to_owned();
        let mut connections = DEFAULT_CONNECTIONS;
        let mut bytes_per_connection = DEFAULT_BYTES_PER_CONNECTION;
        let mut ping_rounds = DEFAULT_PING_ROUNDS;
        let mut args = env::args().skip(1);

        while let Some(arg) = args.next() {
            let mut value = || {
                args.next()
                    .ok_or_else(|| format!("missing value for {arg}"))
            };
            match arg.as_str() {
                "--proxy" => {
                    proxy_addr = value()?
                        .parse()
                        .map_err(|e| format!("invalid --proxy: {e}"))?
                }
                "--socks" => {
                    socks_addr = Some(
                        value()?
                            .parse()
                            .map_err(|e| format!("invalid --socks: {e}"))?,
                    )
                }
                "--echo" => {
                    echo_addr = value()?
                        .parse()
                        .map_err(|e| format!("invalid --echo: {e}"))?
                }
                "--password" => password = value()?,
                "--connections" => {
                    connections = value()?
                        .parse()
                        .map_err(|e| format!("invalid --connections: {e}"))?
                }
                "--bytes-per-connection" => {
                    bytes_per_connection = value()?
                        .parse()
                        .map_err(|e| format!("invalid --bytes-per-connection: {e}"))?
                }
                "--ping-rounds" => {
                    ping_rounds = value()?
                        .parse()
                        .map_err(|e| format!("invalid --ping-rounds: {e}"))?
                }
                "--help" | "-h" => {
                    return Err("usage: trojan_bench [--proxy IP:PORT | --socks IP:PORT] [--echo IP:PORT] [--password PASSWORD] [--connections N] [--bytes-per-connection N] [--ping-rounds N]".to_owned());
                }
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }

        if connections == 0 || bytes_per_connection == 0 || ping_rounds == 0 {
            return Err(
                "connections, bytes-per-connection, and ping-rounds must be positive".to_owned(),
            );
        }
        if !echo_addr.ip().is_ipv4() {
            return Err("the built-in echo target currently requires an IPv4 address".to_owned());
        }

        Ok(Self {
            proxy_addr,
            socks_addr,
            echo_addr,
            password,
            connections,
            bytes_per_connection,
            ping_rounds,
        })
    }
}

fn password_hex(password: &str) -> [u8; 56] {
    let mut hasher = Sha224::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let mut result = [0u8; 56];
    hex::encode_to_slice(digest, &mut result).expect("SHA-224 hex output has a fixed length");
    result
}

async fn connect_trojan(config: &Config, password: &[u8; 56]) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(config.proxy_addr).await?;
    stream.set_nodelay(true)?;

    let target = match config.echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => unreachable!("validated by Config::parse"),
    };
    let mut request = [0u8; 66];
    request[..56].copy_from_slice(password);
    request[56..58].copy_from_slice(b"\r\n");
    request[58] = 1; // CONNECT
    request[59] = 1; // IPv4
    request[60..64].copy_from_slice(&target);
    request[64..66].copy_from_slice(&config.echo_addr.port().to_be_bytes());
    stream.write_all(&request).await?;
    stream.write_all(b"\r\n").await?;
    Ok(stream)
}

async fn connect_socks5(config: &Config, socks_addr: SocketAddr) -> io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks_addr).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [5, 0] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy did not accept no-authentication",
        ));
    }

    let target = match config.echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => unreachable!("validated by Config::parse"),
    };
    let mut request = [0u8; 10];
    request[..4].copy_from_slice(&[5, 1, 0, 1]);
    request[4..8].copy_from_slice(&target);
    request[8..10].copy_from_slice(&config.echo_addr.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 5 || response[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT failed with reply code {}", response[1]),
        ));
    }
    let address_len = match response[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid SOCKS5 response address type {atyp}"),
            ))
        }
    };
    let mut remainder = vec![0u8; address_len + 2];
    stream.read_exact(&mut remainder).await?;
    Ok(stream)
}

async fn connect_proxy(config: &Config, password: &[u8; 56]) -> io::Result<TcpStream> {
    match config.socks_addr {
        Some(socks_addr) => connect_socks5(config, socks_addr).await,
        None => connect_trojan(config, password).await,
    }
}

async fn run_echo_server(listener: TcpListener) -> io::Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let (mut read_half, mut write_half) = stream.split();
            let mut reader = BufReader::with_capacity(IO_CHUNK_SIZE, &mut read_half);
            let _ = tokio::io::copy_buf(&mut reader, &mut write_half).await;
        });
    }
}

async fn transfer(
    mut stream: TcpStream,
    bytes: usize,
    start: Arc<Notify>,
    ready: mpsc::Sender<()>,
) -> io::Result<()> {
    let start_wait = start.notified();
    ready
        .send(())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "benchmark coordinator dropped"))?;
    start_wait.await;

    let payload = vec![0xA5; IO_CHUNK_SIZE];
    let mut received = vec![0u8; IO_CHUNK_SIZE];
    let mut remaining = bytes;
    while remaining > 0 {
        let len = remaining.min(payload.len());
        stream.write_all(&payload[..len]).await?;
        stream.read_exact(&mut received[..len]).await?;
        if received[..len] != payload[..len] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "echo payload mismatch",
            ));
        }
        remaining -= len;
    }
    stream.shutdown().await
}

fn percentile(sorted: &[u128], p: f64) -> u128 {
    let index = ((sorted.len() - 1) as f64 * p).ceil() as usize;
    sorted[index]
}

async fn latency_sample(config: &Config, password: &[u8; 56]) -> io::Result<Vec<u128>> {
    let mut stream = connect_proxy(config, password).await?;
    let mut samples = Vec::with_capacity(config.ping_rounds);
    let mut reply = [0u8; 1];
    for _ in 0..config.ping_rounds {
        let started = Instant::now();
        stream.write_all(&[0x5A]).await?;
        stream.read_exact(&mut reply).await?;
        if reply != [0x5A] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "echo payload mismatch",
            ));
        }
        samples.push(started.elapsed().as_micros());
    }
    stream.shutdown().await?;
    Ok(samples)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse().map_err(io::Error::other)?;
    let listener = TcpListener::bind(config.echo_addr).await?;
    let echo_addr = listener.local_addr()?;
    let echo_task = tokio::spawn(run_echo_server(listener));
    let password = password_hex(&config.password);

    println!(
        "benchmark proxy={} echo={} connections={} bytes_per_connection={} ping_rounds={}",
        config.proxy_addr,
        echo_addr,
        config.connections,
        config.bytes_per_connection,
        config.ping_rounds
    );

    let start = Arc::new(Notify::new());
    let (ready_tx, mut ready_rx) = mpsc::channel(config.connections);
    let mut tasks = Vec::with_capacity(config.connections);
    for _ in 0..config.connections {
        let stream = connect_proxy(&config, &password).await?;
        let start = Arc::clone(&start);
        let ready_tx = ready_tx.clone();
        let bytes = config.bytes_per_connection;
        tasks.push(tokio::spawn(async move {
            transfer(stream, bytes, start, ready_tx).await
        }));
    }
    drop(ready_tx);
    for _ in 0..config.connections {
        ready_rx
            .recv()
            .await
            .ok_or("benchmark connection exited before start")?;
    }

    let started = Instant::now();
    start.notify_waiters();
    for task in tasks {
        task.await??;
    }
    let elapsed = started.elapsed();
    let transferred = config.connections * config.bytes_per_connection;
    let mib_per_sec = transferred as f64 / 1024.0 / 1024.0 / elapsed.as_secs_f64();
    println!(
        "throughput application_bytes={} elapsed_s={:.3} MiB_s={:.2}",
        transferred,
        elapsed.as_secs_f64(),
        mib_per_sec
    );

    let mut samples = latency_sample(&config, &password).await?;
    samples.sort_unstable();
    let mean = samples.iter().sum::<u128>() / samples.len() as u128;
    println!(
        "latency_us p50={} p95={} p99={} mean={} min={}",
        percentile(&samples, 0.50),
        percentile(&samples, 0.95),
        percentile(&samples, 0.99),
        mean,
        samples[0]
    );

    echo_task.abort();
    let _ = tokio::time::timeout(Duration::from_secs(1), echo_task).await;
    Ok(())
}
