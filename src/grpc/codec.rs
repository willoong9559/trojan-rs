use bytes::{BufMut, BytesMut};
use std::io;

pub struct ParsedGrpcHeader {
    pub header_len: usize,
    pub payload_len: usize,
}

/// 解析 gRPC 帧头（兼容 v2ray 格式）
///
/// 帧结构: compression(1) + length(4) + protobuf tag(1) + varint(payload_len) + payload
/// 当数据不足以完成头部解析时，返回 Ok(None)。
pub fn parse_grpc_header(buf: &[u8]) -> io::Result<Option<ParsedGrpcHeader>> {
    if buf.len() < 6 {
        return Ok(None);
    }

    if buf[0] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed gRPC not supported",
        ));
    }

    let grpc_frame_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if buf[5] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected protobuf tag, expected 0x0A",
        ));
    }

    let (payload_len_u64, varint_bytes) = match decode_varint_partial(&buf[6..])? {
        Some(v) => v,
        None => return Ok(None),
    };
    let payload_len = payload_len_u64 as usize;
    let msg_len = 1 + varint_bytes + payload_len;

    if msg_len != grpc_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length mismatch: protobuf section {} != gRPC frame length {}",
                msg_len, grpc_frame_len
            ),
        ));
    }

    Ok(Some(ParsedGrpcHeader {
        header_len: 6 + varint_bytes,
        payload_len,
    }))
}

/// 编码 gRPC 消息帧
pub fn encode_grpc_message(payload: &[u8]) -> BytesMut {
    let mut proto_header = BytesMut::with_capacity(10);
    proto_header.put_u8(0x0A);
    encode_varint(payload.len() as u64, &mut proto_header);

    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;
    let mut buf = BytesMut::with_capacity(5 + proto_header.len() + payload.len());
    buf.put_u8(0x00);
    buf.put_u32(grpc_payload_len);
    buf.extend_from_slice(&proto_header);
    buf.extend_from_slice(payload);

    buf
}

fn decode_varint_partial(data: &[u8]) -> io::Result<Option<(u64, usize)>> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint too long"));
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok(Some((result, i + 1)));
        }

        shift += 7;
    }

    Ok(None)
}

fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
}
