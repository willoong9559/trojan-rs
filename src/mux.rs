use crate::{Server, socks5, utils};
use anyhow::{Context, Result, anyhow};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

const OPTION_DATA: u8 = 0x01;
const OPTION_ERROR: u8 = 0x02;
const BUF_SIZE: usize = 8192;

pub const MUX_COOL_ADDRESS: &str = "v1.mux.cool";
pub const MUX_COOL_PORT: u16 = 9527;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

impl SessionStatus {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(SessionStatus::New),
            0x02 => Ok(SessionStatus::Keep),
            0x03 => Ok(SessionStatus::End),
            0x04 => Ok(SessionStatus::KeepAlive),
            _ => Err(anyhow!("未知的 Mux 会话状态: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetNetwork {
    Tcp = 0x01,
    Udp = 0x02,
}

impl TargetNetwork {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(TargetNetwork::Tcp),
            0x02 => Ok(TargetNetwork::Udp),
            0x00 => Err(anyhow!("缺少目标网络信息")),
            _ => Err(anyhow!("未知的 Mux 目标网络类型: {value}")),
        }
    }
}

#[derive(Debug, Clone)]
struct TargetInfo {
    network: TargetNetwork,
    address: socks5::Address,
    global_id: Option<[u8; 8]>,
}

#[derive(Debug, Clone)]
struct FrameMetadata {
    session_id: u16,
    status: SessionStatus,
    options: u8,
    target: Option<TargetInfo>,
}

impl FrameMetadata {
    fn has_data(&self) -> bool {
        self.options & OPTION_DATA != 0
    }

    fn has_error(&self) -> bool {
        self.options & OPTION_ERROR != 0
    }
}

#[derive(Debug)]
struct MuxFrame {
    metadata: FrameMetadata,
    payload: Vec<u8>,
}

enum FrameReadOutcome {
    Frame(MuxFrame),
    Eof,
}

struct TcpSession {
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    reader_handle: JoinHandle<()>,
    target: socks5::Address,
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    reader_handle: JoinHandle<()>,
    target: socks5::Address,
}

enum MuxSession {
    Tcp(TcpSession),
    Udp(UdpSession),
}

impl MuxSession {
    async fn close(self) {
        match self {
            MuxSession::Tcp(mut session) => {
                if let Some(tx) = session.shutdown_tx.take() {
                    let _ = tx.send(());
                }
                let mut writer = session.writer.lock().await;
                let _ = writer.shutdown().await;
                let _ = session.reader_handle.await;
            }
            MuxSession::Udp(mut session) => {
                if let Some(tx) = session.shutdown_tx.take() {
                    let _ = tx.send(());
                }
                let _ = session.reader_handle.await;
            }
        }
    }
}

enum MuxEvent {
    SessionClosed(u16),
}

pub async fn handle_mux<S>(
    server: Arc<Server>,
    stream: S,
    peer_addr: String,
    initial_data: Vec<u8>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !server.quiet {
        println!("来自 {} 的 Mux 连接已建立", peer_addr);
    }

    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(Mutex::new(writer));
    let mut buffer: VecDeque<u8> = VecDeque::from(initial_data);
    let mut sessions: HashMap<u16, MuxSession> = HashMap::new();
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<MuxEvent>();

    loop {
        while let Ok(event) = event_rx.try_recv() {
            match event {
                MuxEvent::SessionClosed(id) => {
                    sessions.remove(&id);
                }
            }
        }

        match read_frame(&mut reader, &mut buffer).await? {
            FrameReadOutcome::Eof => break,
            FrameReadOutcome::Frame(frame) => {
                process_frame(
                    Arc::clone(&server),
                    &writer,
                    &mut sessions,
                    &event_tx,
                    frame,
                )
                .await?;
            }
        }
    }

    if !server.quiet {
        println!("Mux 连接 {} 已关闭，开始清理会话", peer_addr);
    }

    for (_, session) in sessions.into_iter() {
        session.close().await;
    }

    Ok(())
}

async fn process_frame<S>(
    server: Arc<Server>,
    writer: &Arc<Mutex<WriteHalf<S>>>,
    sessions: &mut HashMap<u16, MuxSession>,
    event_tx: &mpsc::UnboundedSender<MuxEvent>,
    frame: MuxFrame,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    match frame.metadata.status {
        SessionStatus::New => handle_new_session(server, writer, sessions, event_tx, frame).await,
        SessionStatus::Keep => handle_keep_session(server, writer, sessions, frame).await,
        SessionStatus::End => handle_end_session(sessions, frame.metadata.session_id).await,
        SessionStatus::KeepAlive => {
            if frame.metadata.has_data() && !frame.payload.is_empty() && !server.quiet {
                println!(
                    "Mux 会话 {} 收到 {} 字节的 KeepAlive 负载，已忽略",
                    frame.metadata.session_id,
                    frame.payload.len()
                );
            }
            Ok(())
        }
    }
}

async fn handle_end_session(
    sessions: &mut HashMap<u16, MuxSession>,
    session_id: u16,
) -> Result<()> {
    if let Some(session) = sessions.remove(&session_id) {
        session.close().await;
    }
    Ok(())
}

async fn handle_keep_session<S>(
    server: Arc<Server>,
    writer: &Arc<Mutex<WriteHalf<S>>>,
    sessions: &mut HashMap<u16, MuxSession>,
    frame: MuxFrame,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    let session_id = frame.metadata.session_id;
    if let Some(session) = sessions.get_mut(&session_id) {
        match session {
            MuxSession::Tcp(tcp) => {
                if frame.metadata.has_data() {
                    let mut remote_writer = tcp.writer.lock().await;
                    if let Err(e) = remote_writer.write_all(&frame.payload).await {
                        drop(remote_writer);
                        send_end_frame(writer, session_id, true, None).await?;
                        if !server.quiet {
                            println!(
                                "Mux 会话 {} 向 {} 写入失败: {}",
                                session_id,
                                tcp.target.to_key(),
                                utils::describe_io_error(&e)
                            );
                        }
                        if let Some(session) = sessions.remove(&session_id) {
                            session.close().await;
                        }
                    }
                }
            }
            MuxSession::Udp(udp) => {
                if let Some(target) = frame.metadata.target.clone() {
                    udp.target = target.address;
                }
                if frame.metadata.has_data() {
                    let dest = udp.target.to_socket_addr().await?;
                    if let Err(e) = udp.socket.send_to(&frame.payload, dest).await {
                        send_end_frame(writer, session_id, true, None).await?;
                        if !server.quiet {
                            println!(
                                "Mux UDP 会话 {} 发送失败: {}",
                                session_id,
                                utils::describe_io_error(&e)
                            );
                        }
                        if let Some(session) = sessions.remove(&session_id) {
                            session.close().await;
                        }
                    }
                }
            }
        }
    } else if frame.metadata.has_error() && !server.quiet {
        println!("收到未知 Mux 会话 {} 的错误通知", session_id);
    }
    Ok(())
}

async fn handle_new_session<S>(
    server: Arc<Server>,
    writer: &Arc<Mutex<WriteHalf<S>>>,
    sessions: &mut HashMap<u16, MuxSession>,
    event_tx: &mpsc::UnboundedSender<MuxEvent>,
    frame: MuxFrame,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    let metadata = frame.metadata;
    let session_id = metadata.session_id;
    let Some(target) = metadata.target.clone() else {
        return Err(anyhow!("Mux 新建会话缺少目标信息"));
    };

    match target.network {
        TargetNetwork::Tcp => {
            let remote_addr = target.address.to_socket_addr().await?;
            if !server.quiet {
                println!(
                    "Mux 会话 {} 建立 TCP 目标 {}",
                    session_id,
                    target.address.to_key()
                );
            }

            match TcpStream::connect(remote_addr).await {
                Ok(stream) => {
                    let (read_half, write_half) = stream.into_split();
                    let write_half = Arc::new(Mutex::new(write_half));
                    let writer_clone = Arc::clone(writer);
                    let server_clone = Arc::clone(&server);
                    let event_tx_clone = event_tx.clone();
                    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
                    let mut shutdown_holder = Some(shutdown_tx);

                    let reader_handle = tokio::spawn(async move {
                        let mut read_half = read_half;
                        let mut buf = vec![0u8; BUF_SIZE];
                        loop {
                            tokio::select! {
                                _ = &mut shutdown_rx => break,
                                read_res = read_half.read(&mut buf) => {
                                    match read_res {
                                        Ok(0) => {
                                            let _ = send_end_frame(&writer_clone, session_id, false, None).await;
                                            let _ = event_tx_clone.send(MuxEvent::SessionClosed(session_id));
                                            break;
                                        }
                                        Ok(n) => {
                                            if let Err(e) = send_data_frame(&writer_clone, session_id, &buf[..n], None).await {
                                                if !server_clone.quiet {
                                                    println!("Mux 会话 {} 回传数据失败: {}", session_id, e);
                                                }
                                                let _ = event_tx_clone.send(MuxEvent::SessionClosed(session_id));
                                                break;
                                            }
                                        }
                                        Err(err) => {
                                            if !server_clone.quiet {
                                                println!(
                                                    "Mux 会话 {} 读取远端失败: {}",
                                                    session_id,
                                                    utils::describe_io_error(&err)
                                                );
                                            }
                                            let _ = send_end_frame(&writer_clone, session_id, true, None).await;
                                            let _ = event_tx_clone.send(MuxEvent::SessionClosed(session_id));
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    });

                    if metadata.has_data() && !frame.payload.is_empty() {
                        let mut remote_writer = write_half.lock().await;
                        if let Err(e) = remote_writer.write_all(&frame.payload).await {
                            if !server.quiet {
                                println!(
                                    "Mux 会话 {} 写入初始数据失败: {}",
                                    session_id,
                                    utils::describe_io_error(&e)
                                );
                            }
                            drop(remote_writer);
                            if let Some(tx) = shutdown_holder.take() {
                                let _ = tx.send(());
                            }
                            let _ = reader_handle.await;
                            send_end_frame(writer, session_id, true, None).await?;
                            return Ok(());
                        }
                    }

                    sessions.insert(
                        session_id,
                        MuxSession::Tcp(TcpSession {
                            writer: write_half,
                            shutdown_tx: shutdown_holder,
                            reader_handle,
                            target: target.address,
                        }),
                    );
                    Ok(())
                }
                Err(e) => {
                    if !server.quiet {
                        println!(
                            "Mux 会话 {} 连接 {} 失败: {}",
                            session_id,
                            target.address.to_key(),
                            utils::describe_io_error(&e)
                        );
                    }
                    send_end_frame(writer, session_id, true, None).await
                }
            }
        }
        TargetNetwork::Udp => {
            let socket = UdpSocket::bind((IpAddr::from([0, 0, 0, 0]), 0)).await?;
            let socket = Arc::new(socket);
            let remote_addr = target.address.to_socket_addr().await?;

            if metadata.has_data() && !frame.payload.is_empty() {
                socket.send_to(&frame.payload, remote_addr).await?;
            }

            let writer_clone = Arc::clone(writer);
            let server_clone = Arc::clone(&server);
            let event_tx_clone = event_tx.clone();
            let socket_reader = Arc::clone(&socket);
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

            let reader_handle = tokio::spawn(async move {
                let mut buf = vec![0u8; BUF_SIZE];
                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        recv_res = socket_reader.recv_from(&mut buf) => {
                            match recv_res {
                                Ok((n, from)) => {
                                    let target_info = TargetInfo {
                                        network: TargetNetwork::Udp,
                                        address: socket_addr_to_socks5(from),
                                        global_id: None,
                                    };
                                    if let Err(e) = send_data_frame(&writer_clone, session_id, &buf[..n], Some(&target_info)).await {
                                        if !server_clone.quiet {
                                            println!("Mux UDP 会话 {} 回传数据失败: {}", session_id, e);
                                        }
                                        let _ = event_tx_clone.send(MuxEvent::SessionClosed(session_id));
                                        break;
                                    }
                                }
                                Err(err) => {
                                    if !server_clone.quiet {
                                        println!(
                                            "Mux UDP 会话 {} 接收失败: {}",
                                            session_id,
                                            utils::describe_io_error(&err)
                                        );
                                    }
                                    let _ = send_end_frame(&writer_clone, session_id, true, None).await;
                                    let _ = event_tx_clone.send(MuxEvent::SessionClosed(session_id));
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            sessions.insert(
                session_id,
                MuxSession::Udp(UdpSession {
                    socket,
                    shutdown_tx: Some(shutdown_tx),
                    reader_handle,
                    target: target.address,
                }),
            );
            Ok(())
        }
    }
}

async fn send_data_frame<S>(
    writer: &Arc<Mutex<WriteHalf<S>>>,
    session_id: u16,
    payload: &[u8],
    target: Option<&TargetInfo>,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    let metadata = build_metadata(
        session_id,
        SessionStatus::Keep,
        !payload.is_empty(),
        target,
        false,
    );
    let mut writer_guard = writer.lock().await;
    writer_guard.write_all(&metadata).await?;
    if !payload.is_empty() {
        writer_guard
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await?;
        writer_guard.write_all(payload).await?;
    }
    Ok(())
}

async fn send_end_frame<S>(
    writer: &Arc<Mutex<WriteHalf<S>>>,
    session_id: u16,
    has_error: bool,
    target: Option<&TargetInfo>,
) -> Result<()>
where
    S: AsyncWrite + Unpin + Send + 'static,
{
    let metadata = build_metadata(session_id, SessionStatus::End, false, target, has_error);
    let mut writer_guard = writer.lock().await;
    writer_guard.write_all(&metadata).await?;
    Ok(())
}

fn build_metadata(
    session_id: u16,
    status: SessionStatus,
    has_data: bool,
    target: Option<&TargetInfo>,
    has_error: bool,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&session_id.to_be_bytes());
    body.push(status as u8);

    let mut option = 0u8;
    if has_data {
        option |= OPTION_DATA;
    }
    if has_error {
        option |= OPTION_ERROR;
    }
    body.push(option);

    if let Some(target) = target {
        body.push(match target.network {
            TargetNetwork::Tcp => TargetNetwork::Tcp as u8,
            TargetNetwork::Udp => TargetNetwork::Udp as u8,
        });
        body.extend_from_slice(&target.address.port().to_be_bytes());
        encode_address(&target.address, &mut body);
        if let Some(global_id) = target.global_id {
            body.extend_from_slice(&global_id);
        }
    }

    let mut result = Vec::with_capacity(body.len() + 2);
    result.extend_from_slice(&(body.len() as u16).to_be_bytes());
    result.extend_from_slice(&body);
    result
}

fn encode_address(address: &socks5::Address, buffer: &mut Vec<u8>) {
    match address {
        socks5::Address::IPv4(ip, _) => {
            buffer.push(0x01);
            buffer.extend_from_slice(ip);
        }
        socks5::Address::IPv6(ip, _) => {
            buffer.push(0x04);
            buffer.extend_from_slice(ip);
        }
        socks5::Address::Domain(domain, _) => {
            buffer.push(0x03);
            buffer.push(domain.len() as u8);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
}

fn socket_addr_to_socks5(addr: SocketAddr) -> socks5::Address {
    match addr {
        SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
        SocketAddr::V6(v6) => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
    }
}

async fn read_frame<R>(
    reader: &mut ReadHalf<R>,
    buffer: &mut VecDeque<u8>,
) -> Result<FrameReadOutcome>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    match ensure_buffer(reader, buffer, 2).await? {
        BufferState::Closed => return Ok(FrameReadOutcome::Eof),
        BufferState::Ready => {}
    }

    let meta_len = read_u16(buffer);
    match ensure_buffer(reader, buffer, meta_len as usize).await? {
        BufferState::Closed => return Err(anyhow!("Mux 元数据读取不完整")),
        BufferState::Ready => {}
    }
    let meta_bytes = drain_bytes(buffer, meta_len as usize);
    let metadata = parse_metadata(&meta_bytes)?;

    let mut payload = Vec::new();
    if metadata.has_data() {
        match ensure_buffer(reader, buffer, 2).await? {
            BufferState::Closed => return Err(anyhow!("Mux 数据长度字段缺失")),
            BufferState::Ready => {}
        }
        let data_len = read_u16(buffer);
        match ensure_buffer(reader, buffer, data_len as usize).await? {
            BufferState::Closed => return Err(anyhow!("Mux 数据体不完整")),
            BufferState::Ready => {}
        }
        payload = drain_bytes(buffer, data_len as usize);
    }

    Ok(FrameReadOutcome::Frame(MuxFrame { metadata, payload }))
}

enum BufferState {
    Ready,
    Closed,
}

async fn ensure_buffer<R>(
    reader: &mut ReadHalf<R>,
    buffer: &mut VecDeque<u8>,
    required: usize,
) -> Result<BufferState>
where
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    while buffer.len() < required {
        let mut temp = [0u8; BUF_SIZE];
        let n = reader.read(&mut temp).await?;
        if n == 0 {
            return if buffer.is_empty() {
                Ok(BufferState::Closed)
            } else {
                Err(anyhow!("Mux 数据被截断"))
            };
        }
        buffer.extend(temp[..n].iter().copied());
    }
    Ok(BufferState::Ready)
}

fn parse_metadata(bytes: &[u8]) -> Result<FrameMetadata> {
    if bytes.len() < 4 {
        return Err(anyhow!("Mux 元数据长度不足"));
    }
    let session_id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let status = SessionStatus::from_u8(bytes[2])?;
    let options = bytes[3];

    let mut target = None;

    if status == SessionStatus::New
        || (status == SessionStatus::Keep
            && bytes.len() > 4
            && bytes[4] == TargetNetwork::Udp as u8)
    {
        if bytes.len() > 4 {
            let network_byte = bytes[4];
            if network_byte != 0 {
                let (info, _) = parse_target(&bytes[4..], status)?;
                target = Some(info);
            }
        }
    }

    Ok(FrameMetadata {
        session_id,
        status,
        options,
        target,
    })
}

fn parse_target(bytes: &[u8], status: SessionStatus) -> Result<(TargetInfo, usize)> {
    if bytes.len() < 3 {
        return Err(anyhow!("Mux 目标字段不足"));
    }
    let network = TargetNetwork::from_u8(bytes[0])?;
    let port = u16::from_be_bytes([bytes[1], bytes[2]]);
    let mut cursor = 3;

    if bytes.len() <= cursor {
        return Err(anyhow!("Mux 地址信息缺失"));
    }
    let atyp = bytes[cursor];
    cursor += 1;

    let address = match atyp {
        0x01 => {
            if bytes.len() < cursor + 4 {
                return Err(anyhow!("Mux IPv4 地址长度不足"));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&bytes[cursor..cursor + 4]);
            cursor += 4;
            socks5::Address::IPv4(ip, port)
        }
        0x04 => {
            if bytes.len() < cursor + 16 {
                return Err(anyhow!("Mux IPv6 地址长度不足"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[cursor..cursor + 16]);
            cursor += 16;
            socks5::Address::IPv6(ip, port)
        }
        0x03 => {
            if bytes.len() <= cursor {
                return Err(anyhow!("Mux 域名长度字段缺失"));
            }
            let domain_len = bytes[cursor] as usize;
            cursor += 1;
            if bytes.len() < cursor + domain_len {
                return Err(anyhow!("Mux 域名长度不足"));
            }
            let domain = std::str::from_utf8(&bytes[cursor..cursor + domain_len])
                .context("Mux 域名 UTF-8 解析失败")?
                .to_string();
            cursor += domain_len;
            socks5::Address::Domain(domain, port)
        }
        other => return Err(anyhow!("Mux 不支持的地址类型: {other}")),
    };

    let mut global_id = None;
    if status == SessionStatus::New
        && matches!(network, TargetNetwork::Udp)
        && bytes.len() >= cursor + 8
    {
        let mut gid = [0u8; 8];
        gid.copy_from_slice(&bytes[cursor..cursor + 8]);
        cursor += 8;
        global_id = Some(gid);
    }

    Ok((
        TargetInfo {
            network,
            address,
            global_id,
        },
        cursor,
    ))
}

fn drain_bytes(buffer: &mut VecDeque<u8>, len: usize) -> Vec<u8> {
    (0..len).filter_map(|_| buffer.pop_front()).collect()
}

fn read_u16(buffer: &mut VecDeque<u8>) -> u16 {
    let hi = buffer.pop_front().unwrap_or(0);
    let lo = buffer.pop_front().unwrap_or(0);
    u16::from_be_bytes([hi, lo])
}
