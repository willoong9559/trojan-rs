use anyhow::{anyhow, Result};
use bytes::Bytes;

use crate::socks5;

pub const VERSION: u8 = 0;
pub const COMMAND_TCP: u8 = 0x01;
pub const COMMAND_UDP: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    XtlsRprxVision,
}

#[derive(Debug)]
pub struct Request {
    pub version: u8,
    pub user_id: [u8; 16],
    pub command: Command,
    pub flow: Option<Flow>,
    pub addr: socks5::Address,
    pub payload: Bytes,
}

impl Request {
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        // Version, UUID, and addons length.
        if buf.len() < 18 {
            return Ok(None);
        }
        if buf[0] != VERSION {
            return Err(anyhow!("unsupported VLESS version {}", buf[0]));
        }

        let mut user_id = [0_u8; 16];
        user_id.copy_from_slice(&buf[1..17]);
        let addons_len = buf[17] as usize;
        let mut cursor = 18;
        if buf.len() < cursor + addons_len + 1 {
            return Ok(None);
        }
        let flow = decode_addons(&buf[cursor..cursor + addons_len])?;
        cursor += addons_len;

        let command = match buf[cursor] {
            COMMAND_TCP => Command::Tcp,
            COMMAND_UDP => Command::Udp,
            command => return Err(anyhow!("unsupported VLESS command {command}")),
        };
        cursor += 1;
        if buf.len() < cursor + 3 {
            return Ok(None);
        }
        let port = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;

        let addr = match buf[cursor] {
            1 => {
                cursor += 1;
                if buf.len() < cursor + 4 {
                    return Ok(None);
                }
                let mut ip = [0_u8; 4];
                ip.copy_from_slice(&buf[cursor..cursor + 4]);
                cursor += 4;
                socks5::Address::IPv4(ip, port)
            }
            2 => {
                cursor += 1;
                if buf.len() <= cursor {
                    return Ok(None);
                }
                let length = buf[cursor] as usize;
                cursor += 1;
                if length == 0 {
                    return Err(anyhow!("invalid VLESS domain address"));
                }
                if buf.len() < cursor + length {
                    return Ok(None);
                }
                let domain = std::str::from_utf8(&buf[cursor..cursor + length])
                    .map_err(|error| anyhow!("invalid VLESS domain address: {error}"))?
                    .to_string();
                cursor += length;
                socks5::Address::Domain(domain, port)
            }
            3 => {
                cursor += 1;
                if buf.len() < cursor + 16 {
                    return Ok(None);
                }
                let mut ip = [0_u8; 16];
                ip.copy_from_slice(&buf[cursor..cursor + 16]);
                cursor += 16;
                socks5::Address::IPv6(ip, port)
            }
            atyp => return Err(anyhow!("unsupported VLESS address type {atyp}")),
        };

        Ok(Some((
            Self {
                version: VERSION,
                user_id,
                command,
                flow,
                addr,
                payload: Bytes::copy_from_slice(&buf[cursor..]),
            },
            cursor,
        )))
    }

    pub fn response_header(&self) -> [u8; 2] {
        [self.version, 0]
    }
}

/// Decode the small protobuf `encoding.Addons` value used by Xray and mihomo.
/// Vision uses field 1 (the Flow string). Field 2 (`Seed`) is accepted and
/// ignored: it is defined by the VLESS protobuf schema but does not affect the
/// server-side Vision framing.
fn decode_addons(addons: &[u8]) -> Result<Option<Flow>> {
    if addons.is_empty() {
        return Ok(None);
    }
    let mut cursor = 0;
    let mut flow = None;
    while cursor < addons.len() {
        let tag = addons[cursor];
        cursor += 1;
        if tag != 0x0a && tag != 0x12 {
            return Err(anyhow!("unsupported VLESS addons"));
        }
        let (length, consumed) = decode_varint(&addons[cursor..])?;
        cursor += consumed;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| anyhow!("invalid VLESS addons length"))?;
        let value = addons
            .get(cursor..end)
            .ok_or_else(|| anyhow!("truncated VLESS addons"))?;
        if tag == 0x0a {
            flow = Some(match std::str::from_utf8(value)? {
                "xtls-rprx-vision" => Flow::XtlsRprxVision,
                flow => return Err(anyhow!("unsupported VLESS flow {flow:?}")),
            });
        }
        cursor = end;
    }
    Ok(flow)
}

fn decode_varint(input: &[u8]) -> Result<(usize, usize)> {
    let mut value = 0_usize;
    for (index, byte) in input.iter().copied().enumerate() {
        if index >= 10 {
            return Err(anyhow!("invalid VLESS addon length"));
        }
        value |= usize::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok((value, index + 1));
        }
    }
    Err(anyhow!("truncated VLESS addon length"))
}

pub fn parse_uuid(value: &str) -> Result<[u8; 16]> {
    let value = value.trim();
    if value.len() != 36
        || [8, 13, 18, 23]
            .iter()
            .any(|&index| value.as_bytes()[index] != b'-')
    {
        return Err(anyhow!("VLESS password must be a UUID"));
    }

    let mut id = [0_u8; 16];
    let mut output = 0;
    let mut high_nibble = None;
    for (index, byte) in value.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&index) {
            continue;
        }
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(anyhow!("VLESS password must be a UUID")),
        };
        if let Some(high) = high_nibble.take() {
            id[output] = (high << 4) | nibble;
            output += 1;
        } else {
            high_nibble = Some(nibble);
        }
    }
    if output != id.len() || high_nibble.is_some() {
        return Err(anyhow!("VLESS password must be a UUID"));
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{parse_uuid, Command, Flow, Request, COMMAND_TCP};

    #[test]
    fn parses_standard_tcp_request() {
        let mut request = vec![0];
        request.extend_from_slice(&parse_uuid("01234567-89ab-cdef-0123-456789abcdef").unwrap());
        request.extend_from_slice(&[0, 1, 0x01, 0xbb, 1, 127, 0, 0, 1]);
        request.extend_from_slice(b"payload");

        let (decoded, consumed) = Request::decode(&request).unwrap().unwrap();
        assert_eq!(decoded.command, Command::Tcp);
        assert_eq!(decoded.flow, None);
        assert_eq!(decoded.addr.to_key(), "127.0.0.1:443");
        assert_eq!(decoded.payload, "payload");
        assert_eq!(consumed, request.len() - "payload".len());
    }

    #[test]
    fn parses_vision_addon() {
        let mut request = vec![0];
        request.extend_from_slice(&[0; 16]);
        request.extend_from_slice(&[18, 0x0a, 16]);
        request.extend_from_slice(b"xtls-rprx-vision");
        request.extend_from_slice(&[COMMAND_TCP, 0x01, 0xbb, 1, 127, 0, 0, 1]);
        let (decoded, _) = Request::decode(&request).unwrap().unwrap();
        assert_eq!(decoded.flow, Some(Flow::XtlsRprxVision));
    }

    #[test]
    fn accepts_vision_addon_with_seed() {
        let mut request = vec![0];
        request.extend_from_slice(&[0; 16]);
        request.extend_from_slice(&[22, 0x0a, 16]);
        request.extend_from_slice(b"xtls-rprx-vision");
        request.extend_from_slice(&[0x12, 2, 1, 2]);
        request.extend_from_slice(&[COMMAND_TCP, 0x01, 0xbb, 1, 127, 0, 0, 1]);
        let (decoded, _) = Request::decode(&request).unwrap().unwrap();
        assert_eq!(decoded.flow, Some(Flow::XtlsRprxVision));
    }
}
