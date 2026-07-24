//! The retinue half of the endpoint stream gate. retinue's [`Endpoint`] accepts an inbound
//! link as a [`LinkStream`], then echoes lines back over it as an ordinary byte stream. This
//! is the shape a host transport (mere's `Transport`) is implemented against.
//!
//! Driven by `oracle/interop_endpoint_stream.py`.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;

const IDENTITY_SEED: [u8; 64] = [0x11; 64];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = PrivateIdentity::from_secret_bytes(&IDENTITY_SEED);
    let endpoint = Endpoint::new(identity);
    let addr = endpoint.listen_tcp("127.0.0.1:0".parse()?).await?;
    println!("LISTENING {}", addr.port());
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Register so inbound link requests to this destination are accepted (also announces
    // once). An inbound request during the re-announce loop is buffered by the router, so
    // accept picks it up afterwards.
    let name = DestinationName::new("retinue", ["stream"]);
    endpoint.register(name.clone(), b"stream");
    for _ in 0..5 {
        endpoint.announce(&name, b"stream");
        tokio::time::sleep(Duration::from_millis(600)).await;
    }

    println!("WAITING_LINK");
    let mut link = endpoint.accept().await?;
    println!("LINK {}", link.link_id());

    // Echo: read a chunk, write it back prefixed. Runs until the peer closes.
    let mut buf = [0u8; 1024];
    loop {
        match tokio::time::timeout(Duration::from_secs(20), link.read(&mut buf)).await {
            Err(_) => break,
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                println!("RECV {}", String::from_utf8_lossy(&buf[..n]));
                let mut reply = b"echo:".to_vec();
                reply.extend_from_slice(&buf[..n]);
                if link.write_all(&reply).await.is_err() {
                    break;
                }
                let _ = link.flush().await;
                println!("SENT_ECHO");
            }
            Ok(Err(_)) => break,
        }
    }

    println!("DONE");
    Ok(())
}
