//! Multi-interface endpoint: a hub with two interfaces reaches two leaves independently.
//!
//! Proves the R6 plumbing without RNS: a hub endpoint accepts two TCP connections (two
//! interfaces), learns both leaves from their announces, and opens a bidirectional byte
//! stream to each over the correct interface (the bytes are not crossed).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;

/// Spawn a leaf: connect to `hub_addr`, register `aspect`, and echo on any inbound stream.
async fn spawn_leaf(seed: [u8; 64], aspect: &'static str, hub_addr: std::net::SocketAddr) {
    let id = PrivateIdentity::from_secret_bytes(&seed);
    let mut ep = Endpoint::new(id);
    ep.attach_tcp_client(hub_addr).await.unwrap();
    ep.register(DestinationName::new("leaf", [aspect]), aspect.as_bytes());
    // Re-announce a couple of times, then serve inbound streams by echoing.
    tokio::spawn(async move {
        let name = DestinationName::new("leaf", [aspect]);
        for _ in 0..3 {
            ep.announce(&name, aspect.as_bytes());
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        while let Ok(mut stream) = ep.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}

#[tokio::test]
async fn hub_reaches_two_leaves_over_two_interfaces() {
    let hub_id = PrivateIdentity::from_secret_bytes(&[1u8; 64]);
    let mut hub = Endpoint::new(hub_id);
    let addr = hub.listen_tcp("127.0.0.1:0".parse().unwrap()).await.unwrap();

    // Two leaves, each dialing the hub → two interfaces on the hub.
    spawn_leaf([2u8; 64], "a", addr).await;
    spawn_leaf([3u8; 64], "b", addr).await;

    // Learn both leaves from their announces, keyed by destination.
    let mut peers = std::collections::HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while peers.len() < 2 && tokio::time::Instant::now() < deadline {
        if let Ok(Ok(a)) =
            tokio::time::timeout(Duration::from_secs(2), hub.next_announcement()).await
        {
            peers.insert(a.destination, a.identity);
        }
    }
    assert_eq!(peers.len(), 2, "hub should learn both leaves");
    assert_eq!(hub.interface_count(), 2, "hub should have two interfaces");

    // Open a stream to each leaf and check the echo comes back uncrossed.
    for (dest, identity) in peers {
        let mut stream = hub.open(dest, identity).await.expect("open link");
        let msg = format!("hi-{}", &dest.to_string()[..4]);
        stream.write_all(msg.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("read within timeout")
            .expect("read ok");
        let got = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(got, format!("echo:{msg}"), "each leaf echoes its own stream");
    }
}
