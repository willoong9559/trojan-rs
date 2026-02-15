use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use bytes::Bytes;
use h2::client;
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use trojan_rs::grpc::GrpcH2cConnection;

#[tokio::test]
async fn grpc_write_all_completes() {
    let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));
    // Use >32KiB to verify transport splits writes into multiple gRPC frames.
    let payload = Arc::new(vec![0xAB; 40 * 1024]);

    let server_task = tokio::spawn(async move {
        let conn = GrpcH2cConnection::new(server_io)
            .await
            .expect("server handshake should succeed");
        conn.run({
            let done_tx = Arc::clone(&done_tx);
            let payload = Arc::clone(&payload);
            move |mut transport| {
                let done_tx = Arc::clone(&done_tx);
                let payload = Arc::clone(&payload);
                async move {
                    transport
                        .write_all(&payload)
                        .await
                        .expect("write_all should complete");
                    if let Some(tx) = done_tx.lock().expect("mutex poisoned").take() {
                        let _ = tx.send(());
                    }
                    Ok(())
                }
            }
        })
        .await
        .expect("connection run should not fail");
    });

    let (mut send_request, client_conn) = client::Builder::new()
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake should succeed");

    let client_conn_task = tokio::spawn(async move {
        let _ = client_conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("/Tun")
        .body(())
        .expect("request should be valid");
    let (response_future, _request_stream) = send_request
        .send_request(request, true)
        .expect("request send should succeed");

    let response = tokio::time::timeout(Duration::from_secs(5), response_future)
        .await
        .expect("response headers timed out")
        .expect("response future failed");
    let _body = response.into_body();

    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("server write_all timed out")
        .expect("done signal channel closed");

    client_conn_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn grpc_read_large_message_within_limit() {
    let (server_io, client_io) = tokio::io::duplex(8 * 1024 * 1024);
    let (done_tx, done_rx) = oneshot::channel::<()>();
    let done_tx = Arc::new(Mutex::new(Some(done_tx)));
    let payload = vec![0xCD; 1024 * 1024];
    let frame = encode_grpc_frame(&payload).freeze();

    let server_task = tokio::spawn(async move {
        let conn = GrpcH2cConnection::new(server_io)
            .await
            .expect("server handshake should succeed");
        conn.run({
            let done_tx = Arc::clone(&done_tx);
            move |mut transport| {
                let done_tx = Arc::clone(&done_tx);
                async move {
                    let mut buf = vec![0u8; 1024 * 1024];
                    transport
                        .read_exact(&mut buf)
                        .await
                        .expect("read_exact should complete");
                    if let Some(tx) = done_tx.lock().expect("mutex poisoned").take() {
                        let _ = tx.send(());
                    }
                    Ok(())
                }
            }
        })
        .await
        .expect("connection run should not fail");
    });

    let (mut send_request, client_conn) = client::Builder::new()
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake should succeed");

    let client_conn_task = tokio::spawn(async move {
        let _ = client_conn.await;
    });

    let request = Request::builder()
        .method("POST")
        .uri("/Tun")
        .body(())
        .expect("request should be valid");
    let (response_future, mut request_stream) = send_request
        .send_request(request, false)
        .expect("request send should succeed");

    request_stream
        .send_data(frame, true)
        .expect("send_data should succeed");

    let response = tokio::time::timeout(Duration::from_secs(5), response_future)
        .await
        .expect("response headers timed out")
        .expect("response future failed");
    let _body = response.into_body();

    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("server read timed out")
        .expect("done signal channel closed");

    client_conn_task.abort();
    server_task.abort();
}

fn encode_grpc_frame(payload: &[u8]) -> BytesMut {
    let mut proto_header = BytesMut::with_capacity(10);
    proto_header.put_u8(0x0A);
    encode_varint(payload.len() as u64, &mut proto_header);

    let grpc_payload_len = (proto_header.len() + payload.len()) as u32;
    let mut out = BytesMut::with_capacity(5 + grpc_payload_len as usize);
    out.put_u8(0x00);
    out.put_u32(grpc_payload_len);
    out.extend_from_slice(&proto_header);
    out.extend_from_slice(payload);
    out
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
