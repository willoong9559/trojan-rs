use crate::logger::log;
use crate::socks5;
use crate::vmess;

use anyhow::{anyhow, Result};
use bytes::{Bytes, BytesMut};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;

const UDP_TIMEOUT: u64 = 60; // UDP association timeout in seconds;
const BUF_SIZE: usize = 4 * 1024;
// trojan-gfw uses MAX_LENGTH (8 KiB) for both the UDP socket and the encrypted
// stream accumulator. Keep the same per-datagram limit, and close the
// association rather than forwarding a truncated datagram.
const TROJAN_UDP_MAX_PACKET_SIZE: usize = 8 * 1024;

async fn connect_udp_target(target: &socks5::Address) -> Result<UdpSocket> {
    let remote = target.to_socket_addr().await?;
    let socket = match remote {
        SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
        SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
    };
    socket.connect(remote).await?;
    Ok(socket)
}

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
    let socket_uses_v6 = matches!(socket.local_addr(), Ok(SocketAddr::V6(_)));
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let mut read_buf = vec![0_u8; TROJAN_UDP_MAX_PACKET_SIZE];
    // An extra byte lets us recognize (and reject) a packet exceeding the
    // trojan-gfw 8 KiB buffer without ever relaying a truncated payload.
    let mut udp_read_buf = vec![0_u8; TROJAN_UDP_MAX_PACKET_SIZE + 1];
    let mut buffer = BytesMut::with_capacity(TROJAN_UDP_MAX_PACKET_SIZE);
    buffer.extend_from_slice(&initial_payload);
    let mut last_activity = Instant::now();

    'main_loop: loop {
        while !buffer.is_empty() {
            match UdpPacket::decode(&buffer) {
                DecodeResult::Ok(udp_packet, consumed) => {
                    if udp_packet.payload.len() > TROJAN_UDP_MAX_PACKET_SIZE {
                        return Err(anyhow!(
                            "Trojan UDP packet exceeds the 8 KiB trojan-gfw limit"
                        ));
                    }
                    let _ = buffer.split_to(consumed);
                    last_activity = Instant::now();

                    match udp_packet.addr.to_socket_addr().await {
                        Ok(remote_addr) => {
                            let target = match remote_addr {
                                SocketAddr::V4(v4) if socket_uses_v6 => SocketAddr::V6(
                                    SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
                                ),
                                addr => addr,
                            };
                            if let Err(error) = socket.send_to(&udp_packet.payload, target).await {
                                log::debug!(peer = %peer_addr, error = %error, "Failed to send UDP packet");
                            }
                        }
                        Err(error) => {
                            log::debug!(peer = %peer_addr, error = %error, "Failed to resolve UDP target address");
                        }
                    }
                }
                DecodeResult::NeedMoreData => {
                    if buffer.len() > TROJAN_UDP_MAX_PACKET_SIZE {
                        return Err(anyhow!(
                            "incomplete Trojan UDP packet exceeds the 8 KiB trojan-gfw limit"
                        ));
                    }
                    break;
                }
                DecodeResult::Invalid => {
                    log::debug!(peer = %peer_addr, "Invalid UDP packet, closing connection");
                    break 'main_loop;
                }
            }
        }

        let sleep_duration =
            Duration::from_secs(UDP_TIMEOUT).saturating_sub(last_activity.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(sleep_duration) => {
                if last_activity.elapsed().as_secs() >= UDP_TIMEOUT {
                    log::info!(peer = %peer_addr, "UDP associate timeout due to inactivity");
                    break;
                }
            }
            read_result = client_read.read(&mut read_buf) => match read_result {
                Ok(0) => break,
                Ok(length) => buffer.extend_from_slice(&read_buf[..length]),
                Err(error) => {
                    log::debug!(peer = %peer_addr, error = %error, "Error reading from client stream");
                    break;
                }
            },
            recv_result = socket.recv_from(&mut udp_read_buf) => {
                let (length, from_addr) = recv_result?;
                if length > TROJAN_UDP_MAX_PACKET_SIZE {
                    return Err(anyhow!(
                        "UDP response exceeds the 8 KiB trojan-gfw limit"
                    ));
                }

                let addr = match from_addr {
                    SocketAddr::V4(v4) => socks5::Address::IPv4(v4.ip().octets(), v4.port()),
                    SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                        Some(v4) => socks5::Address::IPv4(v4.octets(), v6.port()),
                        None => socks5::Address::IPv6(v6.ip().octets(), v6.port()),
                    },
                };
                let udp_packet = UdpPacket {
                    addr,
                    length: length as u16,
                    payload: Bytes::copy_from_slice(&udp_read_buf[..length]),
                };
                client_write.write_all(&udp_packet.encode()).await?;
                client_write.flush().await?;
                last_activity = Instant::now();
            }
        }
    }

    client_write.shutdown().await?;
    Ok(())
}

/// Handles standard VLESS UDP. The VLESS request header fixes the destination,
/// and body packets are encoded as `u16 length || payload`; connecting the UDP
/// socket to that destination deliberately does not provide Full Cone behavior.
pub async fn handle_vless_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    client_stream: S,
    target: socks5::Address,
    initial_payload: Bytes,
    peer_addr: String,
) -> Result<()> {
    let socket = connect_udp_target(&target).await?;
    log::info!(peer = %peer_addr, "Starting VLESS UDP associate");

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let mut incoming = BytesMut::with_capacity(BUF_SIZE);
    incoming.extend_from_slice(&initial_payload);
    let mut client_read_buf = vec![0_u8; BUF_SIZE];
    let mut udp_read_buf = vec![0_u8; u16::MAX as usize];
    let mut last_activity = Instant::now();

    loop {
        while let Some((packet, consumed)) = decode_vless_udp_packet(&incoming)? {
            let _ = incoming.split_to(consumed);
            if !packet.is_empty() {
                socket.send(&packet).await?;
            }
            last_activity = Instant::now();
        }
        if incoming.len() > u16::MAX as usize + 2 {
            return Err(anyhow!("VLESS UDP packet exceeds maximum size"));
        }

        let idle_remaining =
            std::time::Duration::from_secs(UDP_TIMEOUT).saturating_sub(last_activity.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(idle_remaining) => {
                log::info!(peer = %peer_addr, "VLESS UDP associate timeout due to inactivity");
                break;
            }
            read_result = client_read.read(&mut client_read_buf) => {
                match read_result {
                    Ok(0) => break,
                    Ok(length) => incoming.extend_from_slice(&client_read_buf[..length]),
                    Err(error) => return Err(error.into()),
                }
            }
            recv_result = socket.recv(&mut udp_read_buf) => {
                let length = recv_result?;
                client_write.write_all(&(length as u16).to_be_bytes()).await?;
                client_write.write_all(&udp_read_buf[..length]).await?;
                client_write.flush().await?;
                last_activity = Instant::now();
            }
        }
    }

    client_write.shutdown().await?;
    Ok(())
}

/// Handles VMess UDP over TCP. The VMess header establishes exactly one target;
/// each encrypted VMess record is one UDP datagram in either direction.
pub async fn handle_vmess_udp_associate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut client_stream: vmess::Stream<S>,
    target: socks5::Address,
    peer_addr: String,
) -> Result<()> {
    let socket = connect_udp_target(&target).await?;
    log::info!(peer = %peer_addr, "Starting VMess UDP associate");

    let mut udp_read_buf = vec![0_u8; vmess::MAX_UDP_PACKET_SIZE + 1];
    let mut last_activity = Instant::now();
    loop {
        let idle_remaining =
            std::time::Duration::from_secs(UDP_TIMEOUT).saturating_sub(last_activity.elapsed());
        tokio::select! {
            _ = tokio::time::sleep(idle_remaining) => {
                log::info!(peer = %peer_addr, "VMess UDP associate timeout due to inactivity");
                break;
            }
            packet = client_stream.read_packet() => match packet? {
                Some(packet) => {
                    if !packet.is_empty() {
                        socket.send(&packet).await?;
                    }
                    last_activity = Instant::now();
                }
                None => break,
            },
            received = socket.recv(&mut udp_read_buf) => {
                let length = received?;
                if length > vmess::MAX_UDP_PACKET_SIZE {
                    return Err(anyhow!("VMess UDP response is too large"));
                }
                client_stream.write_packet(&udp_read_buf[..length]).await?;
                last_activity = Instant::now();
            }
        }
    }
    client_stream.shutdown().await?;
    Ok(())
}

fn decode_vless_udp_packet(buf: &[u8]) -> Result<Option<(Bytes, usize)>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < length + 2 {
        return Ok(None);
    }
    Ok(Some((
        Bytes::copy_from_slice(&buf[2..length + 2]),
        length + 2,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    #[tokio::test]
    async fn udp_associate_forwards_datagrams_up_to_trojan_gfw_limit() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_server_addr = udp_server.local_addr().unwrap();
        let target = socks5::Address::IPv4(
            match udp_server_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => panic!("test UDP server must be IPv4"),
            },
            udp_server_addr.port(),
        );
        let initial_packet = UdpPacket {
            addr: target,
            length: 4,
            payload: Bytes::from_static(b"ping"),
        }
        .encode();
        let (client_stream, mut client_side) = tokio::io::duplex(32 * 1024);
        let handle = tokio::spawn(handle_udp_associate(
            client_stream,
            socks5::Address::IPv4([0, 0, 0, 0], 0),
            Bytes::from(initial_packet),
            "127.0.0.1:12345".to_string(),
        ));

        let mut probe = [0_u8; 16];
        let (_, relay_addr) = timeout(Duration::from_secs(3), udp_server.recv_from(&mut probe))
            .await
            .unwrap()
            .unwrap();
        let expected = vec![0x5a; 8 * 1024];
        udp_server.send_to(&expected, relay_addr).await.unwrap();

        let mut encoded = BytesMut::new();
        let mut read_buf = [0_u8; 4096];
        let response = loop {
            match UdpPacket::decode(&encoded) {
                DecodeResult::Ok(packet, _) => break packet,
                DecodeResult::NeedMoreData => {}
                DecodeResult::Invalid => panic!("received an invalid Trojan UDP frame"),
            }
            let length = timeout(Duration::from_secs(3), client_side.read(&mut read_buf))
                .await
                .unwrap()
                .unwrap();
            assert_ne!(length, 0, "UDP associate closed before returning a packet");
            encoded.extend_from_slice(&read_buf[..length]);
        };
        assert_eq!(response.length as usize, expected.len());
        assert_eq!(response.payload.as_ref(), expected.as_slice());

        client_side.shutdown().await.unwrap();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_associate_rejects_remote_datagrams_larger_than_trojan_gfw_limit() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_server_addr = udp_server.local_addr().unwrap();
        let target = socks5::Address::IPv4(
            match udp_server_addr.ip() {
                IpAddr::V4(ip) => ip.octets(),
                IpAddr::V6(_) => panic!("test UDP server must be IPv4"),
            },
            udp_server_addr.port(),
        );
        let initial_packet = UdpPacket {
            addr: target,
            length: 4,
            payload: Bytes::from_static(b"ping"),
        }
        .encode();
        let (client_stream, _client_side) = tokio::io::duplex(32 * 1024);
        let handle = tokio::spawn(handle_udp_associate(
            client_stream,
            socks5::Address::IPv4([0, 0, 0, 0], 0),
            Bytes::from(initial_packet),
            "127.0.0.1:12345".to_string(),
        ));

        let mut probe = [0_u8; 16];
        let (_, relay_addr) = timeout(Duration::from_secs(3), udp_server.recv_from(&mut probe))
            .await
            .unwrap()
            .unwrap();
        udp_server
            .send_to(&vec![0x5a; TROJAN_UDP_MAX_PACKET_SIZE + 1], relay_addr)
            .await
            .unwrap();

        let error = timeout(Duration::from_secs(3), handle)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("trojan-gfw limit"));
    }

    #[tokio::test]
    async fn udp_associate_rejects_oversized_client_packet() {
        let packet = UdpPacket {
            addr: socks5::Address::IPv4([127, 0, 0, 1], 53),
            length: (TROJAN_UDP_MAX_PACKET_SIZE + 1) as u16,
            payload: vec![0; TROJAN_UDP_MAX_PACKET_SIZE + 1].into(),
        }
        .encode();
        let (client_stream, _client_side) = tokio::io::duplex(16 * 1024);

        let error = handle_udp_associate(
            client_stream,
            socks5::Address::IPv4([0, 0, 0, 0], 0),
            Bytes::from(packet),
            "127.0.0.1:12345".to_string(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("trojan-gfw limit"));
    }

    #[tokio::test]
    async fn vless_udp_sends_length_prefixed_initial_packet() {
        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp_server.local_addr().unwrap();
        let (client_stream, mut client_side) = tokio::io::duplex(1024);
        let initial_payload = Bytes::from_static(&[0, 4, b'p', b'i', b'n', b'g']);
        let handle = tokio::spawn(handle_vless_udp_associate(
            client_stream,
            socks5::Address::IPv4(
                match addr.ip() {
                    IpAddr::V4(ip) => ip.octets(),
                    IpAddr::V6(_) => panic!("test UDP server must be IPv4"),
                },
                addr.port(),
            ),
            initial_payload,
            "127.0.0.1:12345".to_string(),
        ));

        let mut received = [0_u8; 16];
        let (length, _) = timeout(Duration::from_secs(3), udp_server.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..length], b"ping");

        client_side.shutdown().await.unwrap();
        handle.await.unwrap().unwrap();
    }
}
