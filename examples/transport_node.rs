//! A pure retinue transport node: listens, enables routing, and forwards between every
//! interface that connects. Hosts no destinations of its own. Port from RETINUE_PORT.

use std::time::Duration;

use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("RETINUE_PORT")?.parse()?;
    let id = PrivateIdentity::from_secret_bytes(&[0xEE; 64]);
    let ep = Endpoint::new(id);
    let addr = ep.listen_tcp(([127, 0, 0, 1], port).into()).await?;
    ep.enable_routing();
    println!(
        "TRANSPORT_NODE_UP {} on {}",
        ep.identity().hash(),
        addr.port()
    );
    // Route forever (until killed). The router runs in background tasks.
    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
