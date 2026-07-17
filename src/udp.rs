use crate::logger::log;
use crate::socks5;

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};

const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;
const BUF_SIZE: usize = 4 * 1024;
const UDP_CHANNEL_BUFFER_SIZE: usize = 64;
const TCP_WRITE_CHANNEL_BUFFER_SIZE: usize = 32;
const TCP_WRITE_BATCH_BYTES: usize = 256 * 1024;
const CLEANUP_TIMEOUT_SECS: u64 = 5;

// UDP Packet for Trojan UDP Associate
#[derive(Debug)]
pub struct UdpPacket {
    pub addr: socks5::Address,
    pub length: u16,
    pub payload: Bytes,
}

#[derive(Debug)]
pub enum DecodeResult {
    Ok(UdpPacket, usize),
    NeedMoreData,
    Invalid,
}

impl UdpPacket {
    pub fn decode(buf: &[u8]) -> DecodeResult {
        if buf.len() < 4 {
            return DecodeResult::NeedMoreData;
        }

        let mut cursor = 0;
        let atyp = buf[cursor];
        cursor += 1;

        let addr = match atyp {
            1 => {
                // IPv4
                if buf.len() < cursor + 6 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv4(ip, port)
            }
            3 => {
                // Domain
                if buf.len() <= cursor {
                    return DecodeResult::NeedMoreData;
                }
                let domain_len = buf[cursor] as usize;
                cursor += 1;
                if buf.len() < cursor + domain_len + 2 {
                    return DecodeResult::NeedMoreData;
                }
                let domain = match std::str::from_utf8(&buf[cursor..cursor + domain_len]) {
                    Ok(s) => s.to_string(),
                    Err(_) => return DecodeResult::Invalid,
                };
                cursor += domain_len;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::Domain(domain, port)
            }
            4 => {
                // IPv6
                if buf.len() < cursor + 18 {
                    return DecodeResult::NeedMoreData;
                }
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
                cursor += 2;
                socks5::Address::IPv6(ip, port)
            }
            _ => return DecodeResult::Invalid,
        };

        // Read length
        if buf.len() < cursor + 2 {
            return DecodeResult::NeedMoreData;
        }
        let length = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        // Read CRLF
        if buf.len() < cursor + 2 {
            return DecodeResult::NeedMoreData;
        }
        if buf[cursor] != b'\r' || buf[cursor + 1] != b'\n' {
            return DecodeResult::Invalid;
        }
        cursor += 2;

        if buf.len() < cursor + length as usize {
            return DecodeResult::NeedMoreData;
        }
        let payload = Bytes::copy_from_slice(&buf[cursor..cursor + length as usize]);
        cursor += length as usize;

        DecodeResult::Ok(
            UdpPacket {
                addr,
                length,
                payload,
            },
            cursor,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        let addr_size = match &self.addr {
            socks5::Address::IPv4(_, _) => 1 + 4 + 2, // type + ip + port
            socks5::Address::Domain(domain, _) => 1 + 1 + domain.len() + 2, // type + len + domain + port
            socks5::Address::IPv6(_, _) => 1 + 16 + 2,                      // type + ip + port
        };
        let total_size = addr_size + 2 + 2 + self.payload.len(); // addr + length + CRLF + payload

        let mut buf = Vec::with_capacity(total_size);

        match &self.addr {
            socks5::Address::IPv4(ip, port) => {
                buf.push(1); // IPv4
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            socks5::Address::Domain(domain, port) => {
                buf.push(3); // Domain
                buf.push(domain.len() as u8);
                buf.extend_from_slice(domain.as_bytes());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            socks5::Address::IPv6(ip, port) => {
                buf.push(4); // IPv6
                buf.extend_from_slice(ip);
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }

        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(&self.payload);

        buf
    }
}

// 处理 UDP Associate 请求
pub async fn handle_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    client_stream: S,
    _bind_addr: socks5::Address,
    initial_payload: Bytes,
    peer_addr: String,
) -> Result<()> {
    log::info!(peer = %peer_addr, "Starting UDP associate");

    let socket = match (|| -> Result<UdpSocket> {
        let raw = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        raw.set_only_v6(false)?;
        raw.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
        raw.set_nonblocking(true)?;
        UdpSocket::from_std(raw.into()).map_err(Into::into)
    })() {
        Ok(socket) => socket,
        Err(e) => {
            log::debug!(error = %e, "IPv6 UDP bind failed, falling back to IPv4");
            UdpSocket::bind("0.0.0.0:0").await?
        }
    };
    let socket = Arc::new(socket);
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let (mut client_read, client_write) = tokio::io::split(client_stream);

    let (udp_tx, mut udp_rx) = mpsc::channel::<(SocketAddr, Bytes)>(UDP_CHANNEL_BUFFER_SIZE);
    let (tcp_write_tx, mut tcp_write_rx) = mpsc::channel::<Vec<u8>>(TCP_WRITE_CHANNEL_BUFFER_SIZE);
    let (cancel_tx, mut cancel_rx) = oneshot::channel::<()>();

    let socket_clone = Arc::clone(&socket);
    let last_activity_clone = Arc::clone(&last_activity);

    let udp_recv_handle = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(BUF_SIZE);
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    break;
                }
                result = {
                    buf.clear();
                    if buf.capacity() < BUF_SIZE {
                        buf.reserve(BUF_SIZE - buf.capacity());
                    }
                    buf.resize(BUF_SIZE, 0);
                    socket_clone.recv_from(&mut buf[..])
                } => {
                    match result {
                        Ok((len, from_addr)) => {
                            *last_activity_clone.lock().await = Instant::now();

                            buf.truncate(len);

                            let data = buf.split_to(len).freeze();

                            match udp_tx.try_send((from_addr, data)) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!("UDP channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break;
                                }
                            }

                            if buf.capacity() > BUF_SIZE * 2 {
                                buf = BytesMut::with_capacity(BUF_SIZE);
                            }
                        }
                        Err(e) => {
                            log::debug!("UDP socket recv error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    let peer_addr_for_write = peer_addr.clone();
    let tcp_write_handle = tokio::spawn(async move {
        let mut client_write = client_write;
        while let Some(encoded) = tcp_write_rx.recv().await {
            let mut batch_bytes = encoded.len();

            if let Err(e) = client_write.write_all(&encoded).await {
                log::debug!(peer = %peer_addr_for_write, error = %e, "Error writing UDP response to client, dropping UDP");
                return;
            }

            while batch_bytes < TCP_WRITE_BATCH_BYTES {
                match tcp_write_rx.try_recv() {
                    Ok(encoded) => {
                        batch_bytes += encoded.len();
                        if let Err(e) = client_write.write_all(&encoded).await {
                            log::debug!(peer = %peer_addr_for_write, error = %e, "Error writing UDP response to client, dropping UDP");
                            return;
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }

            if let Err(e) = client_write.flush().await {
                log::debug!(peer = %peer_addr_for_write, error = %e, "Error flushing UDP response to client, dropping UDP");
                return;
            }
        }

        if let Err(e) = client_write.shutdown().await {
            log::debug!(peer = %peer_addr_for_write, error = %e, "Error shutting down client stream after UDP associate");
        }
    });

    let result = async {
        let mut read_buf = vec![0u8; BUF_SIZE];
        let mut buffer = BytesMut::with_capacity(BUF_SIZE);
        buffer.extend_from_slice(&initial_payload);

        'main_loop: loop {
            while !buffer.is_empty() {
                match UdpPacket::decode(&buffer) {
                    DecodeResult::Ok(udp_packet, consumed) => {
                        let _ = buffer.split_to(consumed);

                        *last_activity.lock().await = Instant::now();

                        match udp_packet.addr.to_socket_addr().await {
                            Ok(remote_addr) => {
                                let target = match remote_addr {
                                    SocketAddr::V4(v4)
                                        if matches!(
                                            socket.local_addr(),
                                            Ok(SocketAddr::V6(_))
                                        ) =>
                                    {
                                        SocketAddr::V6(SocketAddrV6::new(
                                            v4.ip().to_ipv6_mapped(),
                                            v4.port(),
                                            0,
                                            0,
                                        ))
                                    }
                                    addr => addr,
                                };
                                if let Err(e) = socket
                                    .send_to(&udp_packet.payload, target)
                                    .await
                                {
                                    log::debug!(peer = %peer_addr, error = %e, "Failed to send UDP packet");
                                }
                            }
                            Err(e) => {
                                log::debug!(peer = %peer_addr, error = %e, "Failed to resolve UDP target address");
                            }
                        }
                    }
                    DecodeResult::NeedMoreData => {
                        break;
                    }
                    DecodeResult::Invalid => {
                        log::debug!(peer = %peer_addr, "Invalid UDP packet, closing connection");
                        break 'main_loop;
                    }
                }
            }

            let timeout_duration = std::time::Duration::from_secs(UDP_TIMEOUT);
            let time_since_activity = {
                let last = *last_activity.lock().await;
                last.elapsed()
            };
            let sleep_duration = timeout_duration.saturating_sub(time_since_activity);

            tokio::select! {
                _ = tokio::time::sleep(sleep_duration) => {
                    let last = *last_activity.lock().await;
                    if last.elapsed().as_secs() >= UDP_TIMEOUT {
                        log::info!(peer = %peer_addr, "UDP associate timeout due to inactivity");
                        break 'main_loop;
                    }
                }

                read_result = client_read.read(&mut read_buf) => {
                    match read_result {
                        Ok(0) => {
                            break 'main_loop;
                        }
                        Ok(n) => {
                            buffer.extend_from_slice(&read_buf[..n]);
                        }
                        Err(e) => {
                            log::debug!(peer = %peer_addr, error = %e, "Error reading from client stream");
                            break 'main_loop;
                        }
                    }
                }

                packet = udp_rx.recv() => {
                    match packet {
                        Some((from_addr, data)) => {
                            let addr = match from_addr {
                                SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                                SocketAddr::V6(v6) => {
                                    if let Some(v4) = v6.ip().to_ipv4_mapped() {
                                        socks5::Address::IPv4(v4.octets(), v6.port())
                                    } else {
                                        socks5::Address::IPv6(v6.ip().octets(), v6.port())
                                    }
                                }
                            };

                            let udp_packet = UdpPacket {
                                addr,
                                length: data.len() as u16,
                                payload: data,
                            };

                            let encoded = udp_packet.encode();
                            match tcp_write_tx.try_send(encoded) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    log::debug!(peer = %peer_addr, "TCP write channel full, dropping packet");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    break 'main_loop;
                                }
                            }
                        }
                        None => {
                            break 'main_loop;
                        }
                    }
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }.await;

    drop(tcp_write_tx);

    let _ = cancel_tx.send(());

    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        tcp_write_handle,
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "TCP write task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "TCP write task cleanup timeout"
            );
        }
    }

    match tokio::time::timeout(
        std::time::Duration::from_secs(CLEANUP_TIMEOUT_SECS),
        udp_recv_handle,
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            log::warn!(peer = %peer_addr, error = %e, "UDP receive task ended with error");
        }
        Err(_) => {
            log::warn!(
                peer = %peer_addr,
                timeout_secs = CLEANUP_TIMEOUT_SECS,
                "UDP receive task cleanup timeout"
            );
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use tokio::io::AsyncWriteExt;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn udp_associate_sends_initial_payload_packet() {
        let udp_server = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return,
            Err(e) => panic!("UDP server bind should succeed: {e}"),
        };

        let udp_server_addr = udp_server
            .local_addr()
            .expect("UDP server local address should be available");

        let initial_packet = UdpPacket {
            addr: socks5::Address::IPv4(
                match udp_server_addr.ip() {
                    IpAddr::V4(ip) => ip.octets(),
                    IpAddr::V6(_) => panic!("test UDP server must be IPv4"),
                },
                udp_server_addr.port(),
            ),
            length: 4,
            payload: Bytes::from_static(b"ping"),
        }
        .encode();

        let (client_stream, mut client_side) = tokio::io::duplex(1024);
        let handle = tokio::spawn(handle_udp_associate(
            client_stream,
            socks5::Address::IPv4([0, 0, 0, 0], 0),
            Bytes::from(initial_packet),
            "127.0.0.1:12345".to_string(),
        ));

        let mut received = [0u8; 16];
        let (len, _) = timeout(Duration::from_secs(3), udp_server.recv_from(&mut received))
            .await
            .expect("UDP packet from initial payload should arrive")
            .expect("UDP receive should succeed");

        assert_eq!(&received[..len], b"ping");

        client_side
            .shutdown()
            .await
            .expect("client side shutdown should succeed");
        handle
            .await
            .expect("UDP associate task should join")
            .unwrap();
    }
}
