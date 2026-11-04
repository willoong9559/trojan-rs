//! XTLS RPRX Vision framing for a direct VLESS TCP + TLS/REALITY transport.
//!
//! The outer TLS connection is read one complete TLS record at a time.  That
//! discipline is important: once Vision requests raw-copy mode, no bytes from
//! the following raw TCP stream may have been consumed by rustls.

use anyhow::{anyhow, Result};
use bytes::{Buf, BytesMut};
use rand::Rng;
use rustls_reality as rustls;
use std::{
    collections::VecDeque,
    io::{self, BufRead, Cursor, Write},
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::reality::RealityTlsStream;

const HEADER_LEN: usize = 21;
const FRAME_LEN: usize = HEADER_LEN - 16;
const BUFFER_LIMIT: usize = 8192 - HEADER_LEN;
const COMMAND_CONTINUE: u8 = 0;
const COMMAND_END: u8 = 1;
const COMMAND_DIRECT: u8 = 2;

pub struct TlsStream {
    io: TcpStream,
    session: rustls::ServerConnection,
    prefix: BytesMut,
    need_flush: bool,
    read_raw: bool,
    write_raw: bool,
    record_header: [u8; 5],
    record_header_read: usize,
    record_payload: Vec<u8>,
    record_payload_read: usize,
    record: Vec<u8>,
}

impl TlsStream {
    pub async fn accept(
        config: std::sync::Arc<rustls::ServerConfig>,
        io: TcpStream,
    ) -> Result<Self> {
        let mut stream = Self::new(io, rustls::ServerConnection::new(config)?, BytesMut::new());
        while stream.session.is_handshaking() {
            std::future::poll_fn(|cx| Pin::new(&mut stream).poll_drain_tls(cx)).await?;
            let received =
                std::future::poll_fn(|cx| Pin::new(&mut stream).poll_receive_record(cx)).await?;
            if !received {
                return Err(anyhow!("connection closed during TLS handshake"));
            }
        }
        tokio::io::AsyncWriteExt::flush(&mut stream).await?;
        Ok(stream)
    }

    pub fn from_reality(stream: RealityTlsStream) -> Self {
        let (io, session, prefix) = stream.into_vision_parts();
        Self::new(io, session, prefix)
    }

    fn new(io: TcpStream, session: rustls::ServerConnection, prefix: BytesMut) -> Self {
        Self {
            io,
            session,
            prefix,
            need_flush: false,
            read_raw: false,
            write_raw: false,
            record_header: [0; 5],
            record_header_read: 0,
            record_payload: Vec::new(),
            record_payload_read: 0,
            record: Vec::new(),
        }
    }

    fn enable_raw_read(&mut self) -> io::Result<()> {
        if self.record_header_read != 0 || self.record_payload_read != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "cannot switch Vision read path with a partial TLS record",
            ));
        }
        match self.session.reader().fill_buf() {
            Ok(data) if !data.is_empty() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "cannot switch Vision read path with buffered TLS plaintext",
                ));
            }
            Ok(_) => {}
            // An empty rustls plaintext reader may report WouldBlock.  It is
            // safe to transition because record-by-record input guarantees
            // that no subsequent raw TCP bytes have been consumed.
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        self.read_raw = true;
        Ok(())
    }

    fn enable_raw_write(&mut self) {
        self.write_raw = true;
    }

    fn poll_drain_tls(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        while !this.prefix.is_empty() {
            let n = match Pin::new(&mut this.io).poll_write(cx, &this.prefix) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            this.prefix.advance(n);
            this.need_flush = true;
        }
        while this.session.wants_write() {
            let mut writer = PollWriter {
                io: &mut this.io,
                cx,
            };
            match this.session.write_tls(&mut writer) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(_) => this.need_flush = true,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_receive_record(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<bool>> {
        let this = self.as_mut().get_mut();
        while this.record_header_read < 5 {
            let mut buf = ReadBuf::new(&mut this.record_header[this.record_header_read..]);
            match Pin::new(&mut this.io).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) if buf.filled().is_empty() => return Poll::Ready(Ok(false)),
                Poll::Ready(Ok(())) => this.record_header_read += buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if this.record_payload.is_empty() {
            let len = usize::from(u16::from_be_bytes([
                this.record_header[3],
                this.record_header[4],
            ]));
            if len > 16 * 1024 + 256 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS record is too large",
                )));
            }
            this.record_payload.resize(len, 0);
        }
        while this.record_payload_read < this.record_payload.len() {
            let mut buf = ReadBuf::new(&mut this.record_payload[this.record_payload_read..]);
            match Pin::new(&mut this.io).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) if buf.filled().is_empty() => return Poll::Ready(Ok(false)),
                Poll::Ready(Ok(())) => this.record_payload_read += buf.filled().len(),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.record.clear();
        this.record.reserve(5 + this.record_payload.len());
        this.record.extend_from_slice(&this.record_header);
        this.record.extend_from_slice(&this.record_payload);
        this.session
            .read_tls(&mut Cursor::new(this.record.as_slice()))?;
        this.session
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        this.record_header_read = 0;
        this.record_payload.clear();
        this.record_payload_read = 0;
        Poll::Ready(Ok(true))
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_raw {
            return Pin::new(&mut self.io).poll_read(cx, out);
        }
        loop {
            match self.session.reader().fill_buf() {
                Ok(data) if !data.is_empty() => {
                    let n = data.len().min(out.remaining());
                    out.put_slice(&data[..n]);
                    self.session.reader().consume(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(_) => {}
                // rustls reports WouldBlock when its plaintext reader is
                // empty.  That is the normal signal to receive another outer
                // TLS record, not a connection failure.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            std::task::ready!(self.as_mut().poll_drain_tls(cx))?;
            match self.as_mut().poll_receive_record(cx) {
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_raw {
            return Pin::new(&mut self.io).poll_write(cx, data);
        }
        std::task::ready!(self.as_mut().poll_drain_tls(cx))?;
        let n = self.session.writer().write(data)?;
        match self.as_mut().poll_drain_tls(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Pending if n > 0 => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_raw {
            std::task::ready!(self.as_mut().poll_drain_tls(cx))?;
        }
        if self.need_flush {
            std::task::ready!(Pin::new(&mut self.io).poll_flush(cx))?;
            self.need_flush = false;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_raw {
            self.session.send_close_notify();
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

struct PollWriter<'a, 'b> {
    io: &'a mut TcpStream,
    cx: &'a mut Context<'b>,
}
impl Write for PollWriter<'_, '_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, data) {
            Poll::Ready(v) => v,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default)]
struct Traffic {
    packets: u8,
    is_tls: bool,
    tls12_or_newer: bool,
    enable_direct: bool,
    cipher: u16,
    remaining_hello: usize,
}

pub struct Stream {
    inner: TlsStream,
    user_id: [u8; 16],
    input: BytesMut,
    output: BytesMut,
    read_uuid: bool,
    frame: Option<(u8, usize, usize)>,
    traffic: Traffic,
    write_uuid: bool,
    pending: VecDeque<(BytesMut, bool)>,
    current_offset: usize,
    pending_input_len: Option<usize>,
    write_padding: bool,
}

impl Stream {
    pub fn new(inner: TlsStream, user_id: [u8; 16], initial: impl AsRef<[u8]>) -> Self {
        Self {
            inner,
            user_id,
            input: BytesMut::from(initial.as_ref()),
            output: BytesMut::new(),
            read_uuid: true,
            frame: None,
            traffic: Traffic {
                packets: 8,
                ..Traffic::default()
            },
            write_uuid: true,
            pending: VecDeque::new(),
            current_offset: 0,
            pending_input_len: None,
            write_padding: true,
        }
    }
    fn filter_tls(traffic: &mut Traffic, data: &[u8]) {
        if traffic.packets == 0 {
            return;
        }
        traffic.packets -= 1;
        if let Some(i) = find(data, b"\x16\x03\x03") {
            traffic.is_tls = true;
            if data.get(i + 5) == Some(&2) {
                traffic.remaining_hello = data
                    .get(i + 3..i + 5)
                    .map(|v| usize::from(u16::from_be_bytes([v[0], v[1]])) + 5)
                    .unwrap_or(0);
                traffic.tls12_or_newer = true;
                let p = i + 43 + data.get(i + 43).copied().unwrap_or(0) as usize + 1;
                if let Some(v) = data.get(p..p + 2) {
                    traffic.cipher = u16::from_be_bytes([v[0], v[1]]);
                }
            }
        } else if find(data, b"\x16\x03").is_some() {
            traffic.is_tls = true;
        }
        if traffic.remaining_hello > 0 {
            let take = traffic.remaining_hello.min(data.len());
            if data[..take]
                .windows(6)
                .any(|v| v == b"\x00\x2b\x00\x02\x03\x04")
                && traffic.cipher != 0x1305
            {
                traffic.enable_direct = true;
                traffic.packets = 0;
            } else {
                traffic.remaining_hello -= take;
                if traffic.remaining_hello == 0 {
                    traffic.packets = 0;
                }
            }
        }
    }
    fn parse_frames(&mut self) -> io::Result<()> {
        loop {
            if self.frame.is_none() {
                let marker = if self.read_uuid { 16 } else { 0 };
                if self.input.len() < marker + FRAME_LEN {
                    return Ok(());
                }
                if self.read_uuid {
                    if self.input[..16] != self.user_id {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "Vision UUID marker does not match VLESS user",
                        ));
                    }
                    self.input.advance(16);
                    self.read_uuid = false;
                }
                let command = self.input[0];
                let content = usize::from(u16::from_be_bytes([self.input[1], self.input[2]]));
                let padding = usize::from(u16::from_be_bytes([self.input[3], self.input[4]]));
                self.input.advance(FRAME_LEN);
                if command > COMMAND_DIRECT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid Vision command",
                    ));
                }
                self.frame = Some((command, content, padding));
            }
            let (command, content, padding) = self.frame.unwrap();
            if self.input.len() < content + padding {
                return Ok(());
            }
            let body = self.input.split_to(content);
            self.input.advance(padding);
            Self::filter_tls(&mut self.traffic, &body);
            self.output.extend_from_slice(&body);
            self.frame = None;
            if command == COMMAND_END {
                self.frame = Some((COMMAND_END, 0, 0));
                return Ok(());
            }
            if command == COMMAND_DIRECT {
                self.inner.enable_raw_read()?;
                self.frame = Some((COMMAND_DIRECT, 0, 0));
                return Ok(());
            }
        }
    }
    fn make_frame(&mut self, content: &[u8], command: u8) -> BytesMut {
        let padding = if content.len() < 900 {
            if self.traffic.is_tls {
                900 + rand::rng().random_range(0..500) - content.len()
            } else {
                rand::rng().random_range(0..256)
            }
        } else {
            0
        };
        let mut out = BytesMut::with_capacity(
            (if self.write_uuid { 16 } else { 0 }) + FRAME_LEN + content.len() + padding,
        );
        if self.write_uuid {
            out.extend_from_slice(&self.user_id);
            self.write_uuid = false;
        }
        out.extend_from_slice(&[command]);
        out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        out.extend_from_slice(&(padding as u16).to_be_bytes());
        out.extend_from_slice(content);
        out.resize(out.len() + padding, 0);
        out
    }
    fn queue_write(&mut self, data: &[u8]) {
        if !self.write_padding {
            // COMMAND_END keeps the outer TLS transport.  Only COMMAND_DIRECT
            // changes the underlying stream to raw TCP.
            self.pending.push_back((BytesMut::from(data), false));
            return;
        }
        let mut pos = 0;
        while pos < data.len() {
            if self.traffic.is_tls && data[pos..].starts_with(b"\x17\x03\x03") {
                let command = if self.traffic.enable_direct {
                    COMMAND_DIRECT
                } else {
                    COMMAND_END
                };
                let frame = self.make_frame(&data[pos..], command);
                self.pending.push_back((frame, command == COMMAND_DIRECT));
                self.write_padding = false;
                break;
            }
            let mut end = (pos + BUFFER_LIMIT).min(data.len());
            if self.traffic.is_tls {
                if let Some(i) = find(&data[pos + 1..end], b"\x17\x03\x03") {
                    let at = pos + 1 + i;
                    if at - pos >= HEADER_LEN {
                        end = at;
                    }
                }
            }
            let part = &data[pos..end];
            Self::filter_tls(&mut self.traffic, part);
            // If no TLS ServerHello was found in the first packets, Vision
            // falls back to ordinary outer TLS after a final END frame.
            let end_command = !self.traffic.tls12_or_newer && self.traffic.packets == 0;
            let frame = self.make_frame(
                part,
                if end_command {
                    COMMAND_END
                } else {
                    COMMAND_CONTINUE
                },
            );
            self.pending.push_back((frame, false));
            pos = end;
            if end_command {
                self.write_padding = false;
                if pos < data.len() {
                    self.pending
                        .push_back((BytesMut::from(&data[pos..]), false));
                }
                break;
            }
        }
    }
    fn poll_drain_pending(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let this = self.as_mut().get_mut();
            let Some((data, direct)) = this.pending.front() else {
                return Poll::Ready(Ok(()));
            };
            while this.current_offset < data.len() {
                let n = match Pin::new(&mut this.inner).poll_write(cx, &data[this.current_offset..])
                {
                    Poll::Ready(Ok(n)) => n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                this.current_offset += n;
            }
            if *direct && !this.inner.write_raw {
                std::task::ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
                this.inner.enable_raw_write();
            }
            this.pending.pop_front();
            this.current_offset = 0;
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.output.is_empty() {
                let n = self.output.len().min(out.remaining());
                out.put_slice(&self.output.split_to(n));
                return Poll::Ready(Ok(()));
            }
            self.parse_frames()?;
            if !self.output.is_empty() {
                continue;
            }
            if matches!(self.frame, Some((COMMAND_END | COMMAND_DIRECT, 0, 0))) {
                return Pin::new(&mut self.inner).poll_read(cx, out);
            }
            let mut temp = [0_u8; 16 * 1024];
            let mut read = ReadBuf::new(&mut temp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read) {
                Poll::Ready(Ok(())) if read.filled().is_empty() => return Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => self.input.extend_from_slice(read.filled()),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending_input_len.is_none() {
            self.queue_write(data);
            self.pending_input_len = Some(data.len());
        }
        std::task::ready!(self.as_mut().poll_drain_pending(cx))?;
        Poll::Ready(Ok(self.pending_input_len.take().unwrap()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_drain_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|v| v == needle)
}
