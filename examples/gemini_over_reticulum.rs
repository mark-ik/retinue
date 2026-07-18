//! Gemini over Reticulum: a gemtext capsule served and fetched over a real
//! retinue link — no IP, no DNS, no TLS.
//!
//! Two in-process endpoints share a loopback interface: a "capsule" that answers
//! a gemini request, and a client that runs the gemini request/response over the
//! encrypted link. The request/response bytes are exactly what
//! `errand::gemini_exchange` writes and reads; they are inlined here so the
//! example stays dependency-free. The bytes the client prints would feed straight
//! into `errand::gemini::parse` and then a nematic gemtext render.
//!
//! ## Addressing — named (over direct)
//!
//! Two DNS-free ways to name a capsule:
//! - **Direct:** the destination hash *is* the authority — `gemini://<dest-hash>/`.
//! - **Named:** a human name, `gemini://capsule/`, mapped to
//!   `DestinationName::new("gemini", ["capsule"])` and resolved against announces:
//!   the capsule serving it is the announcer whose identity yields that
//!   destination. No hash is known out of band; the name plus the announce is
//!   enough. (This is how Nomad Network addresses nodes.)
//!
//! This example uses **named** addressing — the client resolves `gemini://capsule/`
//! with no hash known up front (see [`resolve_named`]).
//!
//! ## End-of-response — handled
//!
//! Gemini ends a response by closing the connection, and `errand`'s real
//! `gemini_exchange` reads to EOF. `LinkStream` now maps that faithfully:
//! shutting down (or dropping) the stream sends a Reticulum link-close, the peer's
//! router releases the link, and its reader sees a clean EOF. So the capsule below
//! ends its response with `shutdown`, and the client's `read_to_end` terminates —
//! the exact code path `errand::gemini_exchange` runs, unchanged.
//!
//! (For large pages, serving the body as a Reticulum **Resource** — windowed,
//! compressed, with an explicit COMPLETE, the way Nomad Network serves pages — is
//! the natural next step; retinue already implements resources at the protocol
//! level.)

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::hash::AddressHash;
use retinue::identity::{Identity, PrivateIdentity};

/// Named addressing: resolve a gemini authority given as a *name* to its
/// destination + identity by matching announces. The capsule serving
/// `gemini://<name>/` is the announcer whose identity yields
/// `name.destination_hash(identity) == announced_destination`. No hash is known up
/// front; the name plus the announce is enough — the same recompute-and-match a
/// host's directory would use to turn `gemini://capsule/` into a link.
async fn resolve_named(
    endpoint: &Endpoint,
    name: &DestinationName,
    deadline: tokio::time::Instant,
) -> Option<(AddressHash, Identity)> {
    while tokio::time::Instant::now() < deadline {
        if let Ok(Ok(announce)) =
            tokio::time::timeout(Duration::from_millis(400), endpoint.next_announcement()).await
            && name.destination_hash(&announce.identity) == announce.destination
        {
            return Some((announce.destination, announce.identity));
        }
    }
    None
}

const CAPSULE_BODY: &str = "\
# Hello from a Reticulum capsule

This gemtext crossed a Reticulum link. No IP address, no DNS, no TLS: the link is
already end-to-end encrypted, and the destination hash is the peer's identity.

=> gemini://capsule/about   About this capsule
* smolweb and Reticulum are the same ethics at two layers
";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── The capsule: a gemini responder served over Reticulum ──
    let server_id = PrivateIdentity::from_secret_bytes(&[0x2a; 64]);
    let server = Endpoint::new(server_id.clone());
    let addr = server.listen_tcp("127.0.0.1:0".parse()?).await?;
    let name = DestinationName::new("gemini", ["capsule"]);
    let dest = name.destination_hash(server_id.public());
    server.register(name.clone(), b"capsule");
    println!("CAPSULE  gemini://capsule/   (named; resolves to {dest})\n");

    tokio::spawn(async move {
        loop {
            server.announce(&name, b"capsule");
            tokio::select! {
                accepted = server.accept() => {
                    if let Ok(mut link) = accepted {
                        tokio::spawn(async move {
                            // Read the request line: `<url>\r\n` — the gemini wire, unchanged.
                            let mut buf = [0u8; 1024];
                            let n = link.read(&mut buf).await.unwrap_or(0);
                            let request = String::from_utf8_lossy(&buf[..n]);
                            println!("[capsule] request: {}", request.trim_end());
                            // Respond: `20 <mime>\r\n` then the gemtext body.
                            let response = format!("20 text/gemini\r\n{CAPSULE_BODY}");
                            let _ = link.write_all(response.as_bytes()).await;
                            let _ = link.flush().await;
                            // Close the stream to end the response. retinue sends a
                            // link-close the client sees as EOF, so its read-to-end
                            // terminates — gemini's connection-close model, faithfully.
                            let _ = link.shutdown().await;
                        });
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
        }
    });

    // ── The client: resolve the capsule BY NAME, then fetch over the link ──
    let client = Endpoint::new(PrivateIdentity::from_secret_bytes(&[0x18; 64]));
    client.attach_tcp_client(addr).await?;

    // Named addressing: gemini://capsule/ -> DestinationName::new("gemini", ["capsule"]).
    // The client never knew the hash; it resolves (dest, identity) from the announce.
    let authority = "capsule";
    let name = DestinationName::new("gemini", [authority]);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let (dest, identity) = resolve_named(&client, &name, deadline)
        .await
        .ok_or("capsule not found by name")?;
    println!("[client] resolved gemini://{authority}/ -> {dest}");

    let mut link = client.open(dest, identity).await?;

    // ── The gemini exchange over the Reticulum link ──
    // Identical to `errand::gemini_exchange`, inlined so the example is dep-free.
    let url = format!("gemini://{authority}/");
    link.write_all(format!("{url}\r\n").as_bytes()).await?;
    link.flush().await?;

    // Read the whole response to EOF — exactly what errand::gemini_exchange does.
    // The capsule's link-close (above) surfaces as EOF, so this terminates.
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), link.read_to_end(&mut raw)).await??;

    let text = String::from_utf8_lossy(&raw);
    let (status, body) = text.split_once("\r\n").unwrap_or((text.as_ref(), ""));
    println!("\n[client] fetched gemini://{authority}/");
    println!("[client] status line: {status}");
    println!("[client] gemtext body:\n{body}");
    println!("(in mere: these bytes -> errand::gemini::parse -> nematic gemtext render)");

    Ok(())
}
