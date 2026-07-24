//! A retinue endpoint that links to another retinue endpoint, possibly through a transport
//! node. Role from RETINUE_ROLE (initiator|responder), target from RETINUE_ADDR.
//!
//! responder: register a destination, announce it, echo on any inbound stream.
//! initiator: learn the responder's destination from an announce, open a link, send a probe,
//!            and check the echo. Prints LINKED / ECHO_OK so a harness can verify.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;

const RESPONDER_SEED: [u8; 64] = [0x42; 64];

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let role = std::env::var("RETINUE_ROLE").unwrap_or_else(|_| "responder".into());
    let addr: std::net::SocketAddr = std::env::var("RETINUE_ADDR")?.parse()?;
    let name = DestinationName::new("retinue", ["peer"]);

    if role == "responder" {
        let id = PrivateIdentity::from_secret_bytes(&RESPONDER_SEED);
        let ep = Endpoint::new(id.clone());
        ep.attach_tcp_client(addr).await?;
        println!("RESPONDER_DEST {}", name.destination_hash(id.public()));
        ep.register(name.clone(), b"peer");
        // Re-announce so a transport node propagates it, then echo inbound streams.
        for _ in 0..6 {
            ep.announce(&name, b"peer");
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(2), ep.accept()).await
            {
                println!("RESPONDER_ACCEPTED");
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let mut reply = b"echo:".to_vec();
                        reply.extend_from_slice(&buf[..n]);
                        let _ = stream.write_all(&reply).await;
                    }
                });
            }
        }
    } else {
        // Initiator: distinct identity; learn the responder's destination via announce.
        let id = PrivateIdentity::from_secret_bytes(&[0x24; 64]);
        let ep = Endpoint::new(id);
        ep.attach_tcp_client(addr).await?;
        // Announce ourselves too so the transport node has a reverse path to us.
        let me = DestinationName::new("retinue", ["init"]);
        for _ in 0..3 {
            ep.announce(&me, b"init");
            tokio::time::sleep(Duration::from_millis(300)).await;
        }

        let responder_dest =
            name.destination_hash(PrivateIdentity::from_secret_bytes(&RESPONDER_SEED).public());
        // Wait until we have learned the responder's identity from an announce.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
        while ep.resolve(responder_dest).is_none() && tokio::time::Instant::now() < deadline {
            let _ = tokio::time::timeout(Duration::from_millis(500), ep.next_announcement()).await;
            ep.announce(&me, b"init");
        }
        let identity = match ep.resolve(responder_dest) {
            Some(i) => i,
            None => {
                println!("NO_ROUTE");
                return Ok(());
            }
        };
        println!("RESOLVED_RESPONDER");

        match tokio::time::timeout(Duration::from_secs(10), ep.open(responder_dest, identity)).await
        {
            Ok(Ok(mut stream)) => {
                println!("LINKED {}", stream.link_id());
                stream.write_all(b"ping-through").await?;
                stream.flush().await?;
                let mut buf = [0u8; 256];
                match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                    Ok(Ok(n)) if &buf[..n] == b"echo:ping-through" => println!("ECHO_OK"),
                    _ => println!("ECHO_BAD"),
                }
            }
            Ok(Err(e)) => println!("LINK_FAILED {e}"),
            Err(_) => println!("LINK_FAILED timeout"),
        }
    }
    println!("DONE {role}");
    Ok(())
}
