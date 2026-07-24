//! Bidirectional Retinue Resource acceptance across two Tulle direct-PHY radios.
//!
//! The first link publishes from the initiating endpoint and fetches on the
//! accepting endpoint. The second link exercises the complementary endpoint
//! wrapper: the initiator fetches while the accepting endpoint publishes.

use std::sync::Arc;
use std::time::Duration;

use retinue::destination::DestinationName;
use retinue::endpoint::{Endpoint, ResourceTransferConfig};
use retinue::identity::PrivateIdentity;
use retinue::iface::tulle::drive;
use tulle::PhyProfile;
use tulle::airtime::AirtimeBudget;
use tulle::direct_phy_serial::{DirectPhySerialConfig, DirectPhySerialLink};

fn profile() -> PhyProfile {
    PhyProfile {
        frequency_hz: 906_875_000,
        bandwidth_hz: 250_000,
        spreading_factor: 8,
        coding_rate_denominator: 5,
        preamble_symbols: 16,
        sync_word: 0x12,
        explicit_header: true,
        crc: true,
        invert_iq: false,
        tx_power_dbm: 17,
    }
}

fn payload(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let client_port = args.next().unwrap_or_else(|| "COM6".into());
    let server_port = args.next().unwrap_or_else(|| "COM10".into());
    let resource_len = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(4_096);

    let radio_config = DirectPhySerialConfig {
        online_timeout: Duration::from_secs(10),
        transmit_timeout: Duration::from_secs(10),
        ..DirectPhySerialConfig::default()
    };
    let mut client_radio = DirectPhySerialLink::open(
        &client_port,
        profile(),
        AirtimeBudget::new(60_000, 60_000),
        radio_config.clone(),
    )?;
    let mut server_radio = DirectPhySerialLink::open(
        &server_port,
        profile(),
        AirtimeBudget::new(60_000, 60_000),
        radio_config,
    )?;
    tokio::time::timeout(Duration::from_secs(15), client_radio.wait_online()).await??;
    tokio::time::timeout(Duration::from_secs(15), server_radio.wait_online()).await??;
    println!("radios online: {client_port}=client, {server_port}=server");

    let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
    let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let client = Endpoint::new(client_id);
    let server = Arc::new(Endpoint::new(server_id.clone()));
    client.set_link_mtu(255);
    server.set_link_mtu(255);

    let client_driver = tokio::spawn(drive(client.attach_interface(), client_radio));
    let server_driver = tokio::spawn(drive(server.attach_interface(), server_radio));

    let name = DestinationName::new("retinue", ["direct-phy-resource"]);
    let destination = name.destination_hash(server_id.public());
    server.register_resource(name, b"COM6-COM10");
    let announce =
        tokio::time::timeout(Duration::from_secs(20), client.next_announcement()).await??;
    if announce.destination != destination {
        return Err("received the wrong resource destination announce".into());
    }
    println!("discovery: resource destination announced over direct PHY");

    let transfer = ResourceTransferConfig {
        timeout: Duration::from_secs(180),
        retry_interval: Duration::from_secs(3),
        request_window: 1,
    };

    let outbound = payload(resource_len, 0x5252_1001);
    let expected_outbound = outbound.clone();
    let receiver = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut accepted = server.accept_resource().await?;
            accepted.session.set_config(transfer);
            accepted.session.fetch().await
        }
    });
    client
        .publish_resource_with_config(destination, *server_id.public(), &outbound, transfer)
        .await?;
    let received = receiver.await??;
    if received != expected_outbound {
        return Err("client-to-server resource was not byte-exact".into());
    }
    println!("publish: client to server {resource_len} bytes passed");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let inbound = payload(resource_len, 0x5252_1002);
    let expected_inbound = inbound.clone();
    let publisher = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut accepted = server.accept_resource().await?;
            accepted.session.set_config(transfer);
            accepted.session.publish(&inbound).await
        }
    });
    let fetched = client
        .fetch_resource_with_config(destination, *server_id.public(), transfer)
        .await?;
    publisher.await??;
    if fetched != expected_inbound {
        return Err("server-to-client resource was not byte-exact".into());
    }
    println!("fetch: server to client {resource_len} bytes passed");

    client_driver.abort();
    server_driver.abort();
    println!("RETINUE DIRECT-PHY RESOURCE HEADED PASSED");
    Ok(())
}
