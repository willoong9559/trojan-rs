use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

pub struct DecodedGrpcMessage {
    pub consumed: usize,
    pub payload: Bytes,
}

/// 流式解析下一条 gRPC 消息帧（兼容 v2ray 格式）
///
/// 格式：5字节 gRPC 头部 + protobuf 头部 + 数据
/// - 输入数据不足时返回 Ok(None)
/// - 解析成功后会从 buf 中就地消费已解析帧
pub fn decode_next_grpc_message(buf: &mut BytesMut) -> io::Result<Option<DecodedGrpcMessage>> {
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
    let consumed = 5 + grpc_frame_len;

    if buf.len() < consumed {
        return Ok(None);
    }

    let mut frame = buf.split_to(consumed);
    frame.advance(5);

    if frame.is_empty() || frame[0] != 0x0A {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected protobuf tag, expected 0x0A",
        ));
    }

    let (payload_len_u64, varint_bytes) = decode_varint(&frame[1..])?;
    let payload_len = payload_len_u64 as usize;
    let data_start = 1 + varint_bytes;
    let data_end = data_start + payload_len;

    if data_end > frame.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "payload length {} exceeds gRPC frame length {}",
                payload_len, grpc_frame_len
            ),
        ));
    }

    frame.advance(data_start);
    let payload = frame.split_to(payload_len).freeze();

    Ok(Some(DecodedGrpcMessage { consumed, payload }))
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

fn decode_varint(data: &[u8]) -> io::Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        if i >= 10 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "varint too long"));
        }

        result |= ((byte & 0x7F) as u64) << shift;

        if (byte & 0x80) == 0 {
            return Ok((result, i + 1));
        }

        shift += 7;
    }

    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete varint"))
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
