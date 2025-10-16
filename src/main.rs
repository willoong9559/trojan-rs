mod mux;
mod socks5;
mod udp;
mod utils;

use anyhow::{Result, anyhow};
use clap::{Parser, ValueEnum};
use futures_util::{
    StreamExt,
    stream::{SplitSink, SplitStream},
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, accept_async};

// TLS support
use rustls_pemfile::certs;
use std::fs::File;
use std::io::BufReader;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

const BUF_SIZE: usize = 8192;

macro_rules! log_if {
    ($server:expr, $($arg:tt)*) => {
        if !$server.quiet {
            println!($($arg)*);
        }
    };
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    #[value(alias = "ws", alias = "websocket")]
    Websocket,
    Tcp,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHeaderMode {
    #[value(alias = "none")]
    None,
    #[value(alias = "http")]
    Http,
}

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "Trojan WS 服务端", long_about = None)]
pub struct ServerConfig {
    /// 监听地址
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// 监听端口
    #[arg(long, default_value = "35537")]
    port: String,

    /// 认证密码
    #[arg(long)]
    password: String,

    /// TLS 证书路径（可选）
    #[arg(long)]
    cert: Option<String>,

    /// TLS 私钥路径（可选）
    #[arg(long)]
    key: Option<String>,

    /// 静默模式（部署时关闭所有控制台输出）
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// 传输网络
    #[arg(long, default_value = "websocket")]
    network: NetworkMode,

    /// TCP 伪装头部类型（仅当 network=tcp 时生效）
    #[arg(long = "tcp-header", default_value = "none")]
    tcp_header: TcpHeaderMode,
}

pub struct Server {
    pub listener: TcpListener,
    pub password: [u8; 56],
    pub udp_associations: Arc<Mutex<HashMap<String, udp::UdpAssociation>>>,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub quiet: bool,
    pub network: NetworkMode,
    pub tcp_header: TcpHeaderMode,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Ok = 0,
    ErrRead = 1,
    ErrWrite = 2,
    ErrResolve = 3,
    MoreData = 4,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrojanCmd {
    Connect = 1,
    UdpAssociate = 3,
}

#[derive(Debug)]
pub struct TrojanRequest {
    pub password: [u8; 56],
    pub cmd: TrojanCmd,
    pub addr: socks5::Address,
    pub payload: Vec<u8>,
}

impl TrojanRequest {
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 59 {
            return Err(anyhow!("缓冲区长度不足"));
        }

        let mut cursor = 0;

        let mut password = [0u8; 56];
        password.copy_from_slice(&buf[cursor..cursor + 56]);
        cursor += 56;

        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("密码段后缺少 CRLF 结尾"));
        }
        cursor += 2;

        let cmd = match buf[cursor] {
            1 => TrojanCmd::Connect,
            3 => TrojanCmd::UdpAssociate,
            _ => return Err(anyhow!("不支持的命令类型")),
        };
        cursor += 1;

        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                if buf.len() < cursor + 6 {
                    return Err(anyhow!("缓冲区长度不足（IPv4 地址）"));
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv4(ip, port)
            }
            3 => {
                if buf.len() <= cursor {
                    return Err(anyhow!("缓冲区长度不足（域名长度）"));
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return Err(anyhow!("缓冲区长度不足（域名）"));
                }
                let domain = String::from_utf8(buf[cursor..cursor + domain_len].to_vec())?;
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::Domain(domain, port)
            }
            4 => {
                if buf.len() < cursor + 18 {
                    return Err(anyhow!("缓冲区长度不足（IPv6 地址）"));
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv6(ip, port)
            }
            _ => return Err(anyhow!("不支持的地址类型")),
        };

        if buf.len() < cursor + 2 || buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return Err(anyhow!("目标地址后缺少 CRLF 结尾"));
        }
        cursor += 2;

        let payload = buf[cursor..].to_vec();

        Ok((
            TrojanRequest {
                password,
                cmd,
                addr,
                payload,
            },
            cursor,
        ))
    }
}

fn is_incomplete_error(error: &anyhow::Error) -> bool {
    error.to_string().contains("缓冲区长度不足")
}

async fn websocket_to_tcp<S: AsyncWriteExt + Unpin + 'static>(
    mut ws_read: SplitStream<WebSocketStream<S>>,
    mut tcp_write: tokio::io::WriteHalf<TcpStream>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    use futures_util::StreamExt;
    while let Some(msg) = ws_read.next().await {
        match msg? {
            Message::Binary(data) => {
                if let Err(e) = tcp_write.write_all(&data).await {
                    let reason = utils::describe_io_error(&e);
                    return Err(anyhow!("向远端服务器写入数据失败: {}", reason));
                }
            }
            Message::Close(_) => break,
            _ => continue,
        }
    }
    Ok(())
}

async fn tcp_to_websocket<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    mut tcp_read: tokio::io::ReadHalf<TcpStream>,
    mut ws_write: SplitSink<WebSocketStream<S>, Message>,
) -> Result<()> {
    use futures_util::SinkExt;
    let mut buf = vec![0u8; BUF_SIZE];
    loop {
        let n = tcp_read.read(&mut buf).await.map_err(|e| {
            let reason = utils::describe_io_error(&e);
            anyhow!("从远端服务器读取数据失败: {}", reason)
        })?;
        if n == 0 {
            break;
        }
        ws_write
            .send(Message::Binary(buf[..n].to_vec()))
            .await
            .map_err(|e| anyhow!("向 WebSocket 客户端发送数据失败: {}", e))?;
    }
    Ok(())
}

async fn handle_udp_associate<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<S>>,
    mut ws_write: SplitSink<WebSocketStream<S>, Message>,
    _bind_addr: socks5::Address,
    client_info: String,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};

    let socket_key = format!(
        "client_{}_{}",
        client_info,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let udp_association = {
        let mut associations = server.udp_associations.lock().await;

        let bind_socket_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);

        let socket = UdpSocket::bind(bind_socket_addr)
            .await
            .map_err(|e| anyhow!("无法绑定 UDP 套接字到 {}: {}", bind_socket_addr, e))?;

        log_if!(
            server,
            "已为客户端 {} 创建新的 UDP 套接字: {}",
            client_info,
            socket.local_addr()?
        );
        let association = udp::UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);

    let quiet = server.quiet;
    let udp_recv_handle: JoinHandle<()> = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    if !quiet {
                        println!("UDP 接收任务已取消");
                    }
                    break;
                }
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from_addr)) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            *activity_tracker.lock().await = now;

                            if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                                if !quiet {
                                    println!("UDP 通道已关闭，停止接收任务");
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            if !quiet {
                                let reason = utils::describe_io_error(&e);
                                println!("UDP 接收数据出错: {}", reason);
                            }
                            break;
                        }
                    }
                }
            }
        }
        if !quiet {
            println!("UDP 接收任务已结束");
        }
    });

    let result = async {
        loop {
            tokio::select! {
                ws_msg = ws_read.next() => {
                    match ws_msg {
                        Some(Ok(Message::Binary(data))) => {
                            match udp::UdpPacket::decode(&data) {
                                Ok((udp_packet, _)) => {
                                    udp_association.update_activity().await;

                                    match udp_packet.addr.to_socket_addr().await {
                                        Ok(remote_addr) => {
                                            if let Err(e) = udp_association
                                                .socket
                                                .send_to(&udp_packet.payload, remote_addr)
                                                .await
                                            {
                                                let reason = utils::describe_io_error(&e);
                                                log_if!(
                                                    server,
                                                    "向 {} 发送 UDP 数据报失败: {}",
                                                    remote_addr,
                                                    reason
                                                );
                                            } else {
                                                log_if!(server, "已转发 UDP 数据报至 {}", remote_addr);
                                            }
                                        }
                                        Err(e) => {
                                            log_if!(server, "解析远端地址失败: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    log_if!(server, "解码 UDP 数据报失败: {}", e);
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) => {
                            log_if!(server, "WebSocket 连接已关闭");
                            break;
                        }
                        Some(Err(e)) => {
                            log_if!(server, "WebSocket 通道异常: {}", e);
                            break;
                        }
                        None => {
                            log_if!(server, "WebSocket 数据流已结束");
                            break;
                        }
                        _ => continue,
                    }
                }

                udp_msg = udp_rx.recv() => {
                    match udp_msg {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
                            };

                            let udp_packet = udp::UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };

                            let encoded = udp_packet.encode();
                            if let Err(e) = ws_write.send(Message::Binary(encoded)).await {
                                log_if!(server, "向 WebSocket 回传 UDP 数据报失败: {}", e);
                                break;
                            } else {
                                log_if!(server, "已将来自 {} 的 UDP 数据报回传给 WebSocket 客户端", from_addr);
                            }
                        }
                        None => {
                            log_if!(server, "UDP 通道已关闭");
                            break;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    log_if!(server, "开始清理 UDP 会话: {}", socket_key);
    let _ = cancel_tx.send(());

    match tokio::time::timeout(std::time::Duration::from_secs(5), udp_recv_handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                log_if!(server, "UDP 接收任务回收失败: {}", e);
            } else {
                log_if!(server, "UDP 接收任务已安全结束");
            }
        }
        Err(_) => {
            log_if!(server, "警告: UDP 接收任务未在超时时间内结束");
        }
    }

    drop(udp_tx);
    drop(udp_rx);

    {
        let mut associations = server.udp_associations.lock().await;
        if associations.remove(&socket_key).is_some() {
            log_if!(
                server,
                "已移除客户端 {} 的 UDP 会话: {}",
                client_info,
                socket_key
            );
        } else {
            log_if!(server, "警告: UDP 会话 {} 已被移除", socket_key);
        }
    }

    log_if!(server, "UDP 会话 {} 清理完成", socket_key);
    result
}

async fn process_trojan_request<S: AsyncReadExt + AsyncWriteExt + Unpin + 'static>(
    server: Arc<Server>,
    mut ws_read: SplitStream<WebSocketStream<S>>,
    ws_write: SplitSink<WebSocketStream<S>, Message>,
    peer_addr: String,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + 'static,
{
    let msg = match ws_read.next().await {
        Some(Ok(Message::Binary(data))) => data,
        Some(Ok(Message::Close(_))) => return Ok(()),
        Some(Err(e)) => return Err(e.into()),
        _ => return Err(anyhow!("期望接收到二进制消息")),
    };

    let (request, _consumed) = TrojanRequest::decode(&msg)?;

    let expected_password: [u8; 56] = server.password;
    if request.password != expected_password {
        log_if!(server, "WebSocket 客户端提供了错误的密码");
        return Err(anyhow!("认证密码不正确"));
    }

    match request.cmd {
        TrojanCmd::Connect => {
            log_if!(
                server,
                "开始处理到 {} 的 TCP CONNECT 请求",
                request.addr.to_key()
            );

            let remote_addr = request.addr.to_socket_addr().await?;
            let remote_stream = TcpStream::connect(remote_addr).await.map_err(|e| {
                let reason = utils::describe_io_error(&e);
                anyhow!("无法连接到远端服务器 {}: {}", remote_addr, reason)
            })?;
            log_if!(server, "已连接到远端服务器 {}", remote_addr);

            let (remote_read, mut remote_write) = tokio::io::split(remote_stream);

            if !request.payload.is_empty() {
                if let Err(e) = remote_write.write_all(&request.payload).await {
                    let reason = utils::describe_io_error(&e);
                    log_if!(server, "写入初始负载失败: {}", reason);
                    return Err(anyhow!(
                        "向远端服务器 {} 写入初始负载失败: {}",
                        remote_addr,
                        reason
                    ));
                }
                log_if!(server, "已写入 {} 字节的初始负载", request.payload.len());
            }

            log_if!(server, "开始建立 TCP 双向转发");

            tokio::select! {
                result = websocket_to_tcp(ws_read, remote_write) => {
                    if let Err(e) = result {
                        log_if!(server, "WebSocket 到 TCP 转发出错: {}", e);
                    } else {
                        log_if!(server, "WebSocket 到 TCP 转发结束");
                    }
                },
                result = tcp_to_websocket(remote_read, ws_write) => {
                    if let Err(e) = result {
                        log_if!(server, "TCP 到 WebSocket 转发出错: {}", e);
                    } else {
                        log_if!(server, "TCP 到 WebSocket 转发结束");
                    }
                },
            }

            log_if!(server, "{} 的 TCP 连接已关闭", peer_addr);
        }

        TrojanCmd::UdpAssociate => {
            log_if!(
                server,
                "开始处理目标 {} 的 UDP ASSOCIATE 请求",
                request.addr.to_key()
            );

            if let Err(e) = handle_udp_associate(
                Arc::clone(&server),
                ws_read,
                ws_write,
                request.addr,
                peer_addr.clone(),
            )
            .await
            {
                log_if!(server, "{} 的 UDP 会话发生错误: {}", peer_addr, e);
                return Err(e);
            }

            log_if!(server, "{} 的 UDP 会话已结束", peer_addr);
        }
    }

    Ok(())
}

async fn perform_http_header<S>(server: &Server, stream: &mut S, peer_addr: &str) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buffer = Vec::new();
    let mut temp = vec![0u8; BUF_SIZE];

    loop {
        let n = stream
            .read(&mut temp)
            .await
            .map_err(|e| anyhow!("读取 HTTP 伪装头部失败: {}", utils::describe_io_error(&e)))?;

        if n == 0 {
            return Err(anyhow!("{} 在发送 HTTP 伪装头部前就关闭了连接", peer_addr));
        }

        buffer.extend_from_slice(&temp[..n]);

        if let Some(idx) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_bytes = &buffer[..idx + 4];
            let header_text = String::from_utf8_lossy(header_bytes);
            if !server.quiet {
                println!(
                    "收到来自 {} 的 HTTP 伪装请求:\n{}",
                    peer_addr,
                    header_text.trim_end()
                );
            }

            let response =
                b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n";
            stream
                .write_all(response)
                .await
                .map_err(|e| anyhow!("返回 HTTP 伪装响应失败: {}", utils::describe_io_error(&e)))?;
            stream.flush().await.map_err(|e| {
                anyhow!("刷新 HTTP 响应缓冲区失败: {}", utils::describe_io_error(&e))
            })?;

            return Ok(buffer[idx + 4..].to_vec());
        }

        if buffer.len() > 16 * 1024 {
            return Err(anyhow!("HTTP 伪装头部超过 16KB，拒绝处理"));
        }
    }
}

async fn handle_udp_associate_over_tcp<S>(
    server: Arc<Server>,
    stream: S,
    _bind_addr: socks5::Address,
    client_info: String,
    mut pending: Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    let socket_key = format!(
        "client_{}_{}",
        client_info,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );

    let udp_association = {
        let mut associations = server.udp_associations.lock().await;
        let bind_socket_addr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)), 0);

        let socket = UdpSocket::bind(bind_socket_addr)
            .await
            .map_err(|e| anyhow!("无法绑定 UDP 套接字到 {}: {}", bind_socket_addr, e))?;

        log_if!(
            server,
            "已为客户端 {} 创建新的 UDP 套接字: {}",
            client_info,
            socket.local_addr()?
        );

        let association = udp::UdpAssociation::new(socket);
        associations.insert(socket_key.clone(), association.clone());
        association
    };

    let (udp_tx, mut udp_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&udp_association.socket);
    let udp_tx_clone = udp_tx.clone();
    let activity_tracker = Arc::clone(&udp_association.last_activity);
    let quiet = server.quiet;

    let udp_recv_handle: JoinHandle<()> = tokio::spawn(async move {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut cancel_rx = cancel_rx;
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    if !quiet {
                        println!("UDP 接收任务已取消");
                    }
                    break;
                }
                result = socket_clone.recv_from(&mut buf) => {
                    match result {
                        Ok((len, from_addr)) => {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            *activity_tracker.lock().await = now;

                            if udp_tx_clone.send((from_addr, buf[..len].to_vec())).is_err() {
                                if !quiet {
                                    println!("UDP 通道已关闭，停止接收任务");
                                }
                                break;
                            }
                        }
                        Err(e) => {
                            if !quiet {
                                let reason = utils::describe_io_error(&e);
                                println!("UDP 接收数据出错: {}", reason);
                            }
                            break;
                        }
                    }
                }
            }
        }

        if !quiet {
            println!("UDP 接收任务已结束");
        }
    });

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut read_buf = vec![0u8; BUF_SIZE];

    let result = async {
        loop {
            loop {
                match udp::UdpPacket::decode(&pending) {
                    Ok((udp_packet, consumed)) => {
                        udp_association.update_activity().await;
                        match udp_packet.addr.to_socket_addr().await {
                            Ok(remote_addr) => {
                                if let Err(e) = udp_association
                                    .socket
                                    .send_to(&udp_packet.payload, remote_addr)
                                    .await
                                {
                                    let reason = utils::describe_io_error(&e);
                                    log_if!(
                                        server,
                                        "向 {} 发送 UDP 数据报失败: {}",
                                        remote_addr,
                                        reason
                                    );
                                } else {
                                    log_if!(server, "已转发 UDP 数据报至 {}", remote_addr);
                                }
                            }
                            Err(e) => {
                                log_if!(server, "解析远端地址失败: {}", e);
                            }
                        }

                        pending.drain(..consumed);
                        continue;
                    }
                    Err(e) => {
                        if is_incomplete_error(&e) {
                            break;
                        } else {
                            log_if!(server, "解码 UDP 数据报失败: {}", e);
                            return Err(e);
                        }
                    }
                }
            }

            tokio::select! {
                read_result = reader.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => {
                            log_if!(server, "客户端 TCP 流已关闭");
                            break;
                        }
                        Ok(n) => {
                            pending.extend_from_slice(&read_buf[..n]);
                        }
                        Err(e) => {
                            let reason = utils::describe_io_error(&e);
                            log_if!(server, "从客户端读取 UDP 负载失败: {}", reason);
                            return Err(anyhow!("从客户端读取 UDP 负载失败: {}", reason));
                        }
                    }
                }
                udp_msg = udp_rx.recv() => {
                    match udp_msg {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
                            };

                            let udp_packet = udp::UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };

                            let encoded = udp_packet.encode();
                            if let Err(e) = writer.write_all(&encoded).await {
                                let reason = utils::describe_io_error(&e);
                                log_if!(server, "向客户端写回 UDP 数据报失败: {}", reason);
                                return Err(anyhow!("向客户端写回 UDP 数据报失败: {}", reason));
                            } else {
                                log_if!(
                                    server,
                                    "已将来自 {} 的 UDP 数据报回传给客户端",
                                    from_addr
                                );
                            }
                        }
                        None => {
                            log_if!(server, "UDP 通道已关闭");
                            break;
                        }
                    }
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    log_if!(server, "开始清理 UDP 会话: {}", socket_key);
    let _ = cancel_tx.send(());

    match tokio::time::timeout(std::time::Duration::from_secs(5), udp_recv_handle).await {
        Ok(join_result) => {
            if let Err(e) = join_result {
                log_if!(server, "UDP 接收任务回收失败: {}", e);
            } else {
                log_if!(server, "UDP 接收任务已安全结束");
            }
        }
        Err(_) => {
            log_if!(server, "警告: UDP 接收任务未在超时时间内结束");
        }
    }

    drop(udp_tx);
    drop(udp_rx);

    {
        let mut associations = server.udp_associations.lock().await;
        if associations.remove(&socket_key).is_some() {
            log_if!(
                server,
                "已移除客户端 {} 的 UDP 会话: {}",
                client_info,
                socket_key
            );
        } else {
            log_if!(server, "警告: UDP 会话 {} 已被移除", socket_key);
        }
    }

    log_if!(server, "UDP 会话 {} 清理完成", socket_key);
    result
}

async fn handle_tcp_stream<S>(server: Arc<Server>, mut stream: S, peer_addr: String) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    log_if!(server, "来自 {} 的 TCP 连接已建立", peer_addr);

    let mut buffer = if server.tcp_header == TcpHeaderMode::Http {
        perform_http_header(&server, &mut stream, &peer_addr).await?
    } else {
        Vec::new()
    };

    let mut temp = vec![0u8; BUF_SIZE];
    let request = loop {
        match TrojanRequest::decode(&buffer) {
            Ok((request, consumed)) => {
                buffer.drain(..consumed + request.payload.len());
                break request;
            }
            Err(e) => {
                if is_incomplete_error(&e) {
                    let n = stream.read(&mut temp).await.map_err(|ioe| {
                        anyhow!(
                            "读取 Trojan 握手数据失败: {}",
                            utils::describe_io_error(&ioe)
                        )
                    })?;
                    if n == 0 {
                        return Err(anyhow!("{} 在发送完整握手数据前关闭了连接", peer_addr));
                    }
                    buffer.extend_from_slice(&temp[..n]);
                } else {
                    return Err(e);
                }
            }
        }
    };

    if request.password != server.password {
        log_if!(server, "TCP 客户端提供了错误的密码");
        return Err(anyhow!("认证密码不正确"));
    }

    let TrojanRequest {
        password: _,
        cmd,
        addr,
        payload,
    } = request;

    match cmd {
        TrojanCmd::Connect => {
            if let socks5::Address::Domain(domain, port) = &addr {
                if domain == mux::MUX_COOL_ADDRESS && *port == mux::MUX_COOL_PORT {
                    log_if!(server, "检测到 Trojan Mux 请求，目标为 {}:{}", domain, port);
                    return mux::handle_mux(Arc::clone(&server), stream, peer_addr, payload).await;
                }
            }

            log_if!(server, "开始处理到 {} 的 TCP CONNECT 请求", addr.to_key());

            let remote_addr = addr.to_socket_addr().await?;
            let mut remote_stream = TcpStream::connect(remote_addr).await.map_err(|e| {
                let reason = utils::describe_io_error(&e);
                anyhow!("无法连接到远端服务器 {}: {}", remote_addr, reason)
            })?;
            log_if!(server, "已连接到远端服务器 {}", remote_addr);

            if !payload.is_empty() {
                if let Err(e) = remote_stream.write_all(&payload).await {
                    let reason = utils::describe_io_error(&e);
                    log_if!(server, "写入初始负载失败: {}", reason);
                    return Err(anyhow!(
                        "向远端服务器 {} 写入初始负载失败: {}",
                        remote_addr,
                        reason
                    ));
                }
                log_if!(server, "已写入 {} 字节的初始负载", payload.len());
            }

            log_if!(server, "开始建立 TCP 双向转发");

            match tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await {
                Ok((_from_client, _from_server)) => {
                    log_if!(server, "TCP 双向转发已结束");
                }
                Err(e) => {
                    let reason = utils::describe_io_error(&e);
                    log_if!(server, "TCP 双向转发出错: {}", reason);
                }
            }

            log_if!(server, "{} 的 TCP 连接已关闭", peer_addr);
            Ok(())
        }
        TrojanCmd::UdpAssociate => {
            log_if!(
                server,
                "开始处理目标 {} 的 UDP ASSOCIATE 请求",
                addr.to_key()
            );

            handle_udp_associate_over_tcp(
                Arc::clone(&server),
                stream,
                addr,
                peer_addr.clone(),
                payload,
            )
            .await?;
            log_if!(server, "{} 的 UDP 会话已结束", peer_addr);
            Ok(())
        }
    }
}

async fn handle_websocket_tls(server: Arc<Server>, stream: TlsStream<TcpStream>) -> Result<()> {
    let peer_addr = stream
        .get_ref()
        .0
        .peer_addr()
        .ok()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "未知".to_string());
    let ws_stream = accept_async(stream).await?;
    log_if!(server, "来自 {} 的 WebSocket 连接已建立", peer_addr);

    let (ws_write, ws_read) = ws_stream.split();
    process_trojan_request(server, ws_read, ws_write, peer_addr).await
}

async fn handle_websocket(server: Arc<Server>, stream: TcpStream) -> Result<()> {
    let peer_addr = stream
        .peer_addr()
        .ok()
        .map(|a| a.to_string())
        .unwrap_or_else(|| "未知".to_string());
    let ws_stream = accept_async(stream).await?;
    log_if!(server, "来自 {} 的 WebSocket 连接已建立", peer_addr);

    let (ws_write, ws_read) = ws_stream.split();
    process_trojan_request(server, ws_read, ws_write, peer_addr).await
}

fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)?;
    let mut reader = BufReader::new(cert_file);
    let certs = certs(&mut reader).collect::<Result<Vec<_>, _>>()?;

    if certs.is_empty() {
        return Err(anyhow!("{} 中未找到有效的证书", cert_path));
    }

    let key_file = File::open(key_path)?;
    let mut reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut reader)?;

    let key = key.ok_or_else(|| anyhow!("{} 中未找到私钥", key_path))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

impl Server {
    pub async fn run(self) -> Result<()> {
        let server = Arc::new(self);
        log_if!(
            server,
            "服务已启动，监听地址为 {}",
            server.listener.local_addr()?
        );

        if server.tls_acceptor.is_some() {
            log_if!(server, "TLS 已启用");
        } else {
            log_if!(server, "未启用 TLS，将以明文模式运行");
        }

        let server_cleanup = Arc::clone(&server);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_secs(udp::UDP_TIMEOUT / 2));
            let quiet = server_cleanup.quiet;
            loop {
                interval.tick().await;
                let mut associations = server_cleanup.udp_associations.lock().await;
                let mut keys_to_remove = Vec::new();

                for (key, association) in associations.iter() {
                    if association.is_inactive(udp::UDP_TIMEOUT).await {
                        if !quiet {
                            println!("检测到需清理的 UDP 会话: {}", key);
                        }
                        keys_to_remove.push(key.clone());
                    }
                }

                for key in keys_to_remove {
                    if associations.remove(&key).is_some() {
                        if !quiet {
                            println!("已移除超时的 UDP 会话: {}", key);
                        }
                    }
                }

                if !associations.is_empty() {
                    if !quiet {
                        println!("当前活跃的 UDP 会话数量: {}", associations.len());
                    }
                    for (key, association) in associations.iter() {
                        let client_count = association.get_client_count().await;
                        let last_activity = association.get_last_activity().await;
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs();
                        if !quiet {
                            println!(
                                "  {}: 活跃客户端 {} 个，最近活动 {} 秒前",
                                key,
                                client_count,
                                now - last_activity
                            );
                        }
                    }
                }
            }
        });

        loop {
            match server.listener.accept().await {
                Ok((stream, addr)) => {
                    log_if!(server, "收到来自 {} 的新连接", addr);
                    let server_clone = Arc::clone(&server);
                    tokio::spawn(async move {
                        let quiet = server_clone.quiet;
                        let result = async {
                            match server_clone.network {
                                NetworkMode::Websocket => {
                                    if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                        match tls_acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                if !quiet {
                                                    println!("来自 {} 的 TLS 握手成功", addr);
                                                }
                                                handle_websocket_tls(server_clone, tls_stream).await
                                            }
                                            Err(e) => {
                                                return Err(anyhow!("TLS 握手失败: {}", e));
                                            }
                                        }
                                    } else {
                                        handle_websocket(server_clone, stream).await
                                    }
                                }
                                NetworkMode::Tcp => {
                                    if let Some(ref tls_acceptor) = server_clone.tls_acceptor {
                                        match tls_acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                if !quiet {
                                                    println!("来自 {} 的 TLS 握手成功", addr);
                                                }
                                                handle_tcp_stream(
                                                    server_clone,
                                                    tls_stream,
                                                    addr.to_string(),
                                                )
                                                .await
                                            }
                                            Err(e) => {
                                                return Err(anyhow!("TLS 握手失败: {}", e));
                                            }
                                        }
                                    } else {
                                        handle_tcp_stream(server_clone, stream, addr.to_string())
                                            .await
                                    }
                                }
                            }
                        }
                        .await;

                        if let Err(e) = result {
                            if !quiet {
                                println!("处理 {} 的连接时出错: {}", addr, e);
                            }
                        } else {
                            if !quiet {
                                println!("来自 {} 的连接已正常结束", addr);
                            }
                        }
                    });
                }
                Err(e) => {
                    log_if!(server, "接受新连接失败: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

pub async fn build_server(config: ServerConfig) -> Result<Server> {
    let addr: String = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(addr).await?;

    let password = utils::password_to_hex(&config.password);

    let tls_acceptor = match (&config.cert, &config.key) {
        (Some(cert_path), Some(key_path)) => {
            if !config.quiet {
                println!("正在加载 TLS 证书: {}, {}", cert_path, key_path);
            }
            Some(load_tls_config(cert_path, key_path)?)
        }
        (None, None) => {
            if !config.quiet {
                println!("未提供 TLS 证书，将以明文模式运行");
            }
            None
        }
        _ => {
            return Err(anyhow!("--cert 与 --key 参数需同时提供或同时省略"));
        }
    };

    Ok(Server {
        listener,
        password,
        udp_associations: Arc::new(Mutex::new(HashMap::new())),
        tls_acceptor,
        quiet: config.quiet,
        network: config.network,
        tcp_header: config.tcp_header,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = ServerConfig::parse();
    let server = build_server(config).await?;
    server.run().await
}
