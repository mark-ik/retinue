//! Two-RNode acceptance for Retinue's Tulle interface.
//!
//! Establishes a reliable stream, performs a bidirectional exchange, then
//! publishes and fetches a multi-packet resource over the same two radios.

use std::sync::Arc;
use std::time::Duration;

use retinue::destination::DestinationName;
use retinue::endpoint::{Endpoint, ResourceTransferConfig};
use retinue::identity::PrivateIdentity;
use retinue::iface::tulle::drive;
use retinue::packet::Packet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tulle::airtime::AirtimeBudget;
use tulle::link::Received;
use tulle::lora::{CodingRate, LoRaParams};
use tulle::radio_io::PacketRadio;
use tulle::serial::TransmitError;
use tulle::serial::{RNodeSerialLink, SerialPumpConfig};

struct TraceRadio<R> {
    name: &'static str,
    inner: R,
}

impl<R> TraceRadio<R> {
    fn new(name: &'static str, inner: R) -> Self {
        Self { name, inner }
    }

    fn print(name: &str, direction: &str, frame: &[u8]) {
        match Packet::decode(frame) {
            Ok(packet) => eprintln!(
                "{} {direction} {} bytes {:?} context={:#04x} payload={}",
                name,
                frame.len(),
                packet.packet_type,
                packet.context,
                packet.payload.len()
            ),
            Err(_) => eprintln!("{} {direction} {} undecodable bytes", name, frame.len()),
        }
    }
}

impl<R: PacketRadio> PacketRadio for TraceRadio<R> {
    fn max_frame_len(&self) -> usize {
        self.inner.max_frame_len()
    }

    fn send_frame(
        &self,
        frame: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<Duration, TransmitError>> + Send {
        Self::print(self.name, "tx", &frame);
        self.inner.send_frame(frame)
    }

    fn recv_frame(&mut self) -> impl std::future::Future<Output = Option<Received>> + Send {
        let name = self.name;
        let received = self.inner.recv_frame();
        async move {
            let received = received.await;
            if let Some(received) = &received {
                Self::print(name, "rx", &received.frame);
            }
            received
        }
    }
}

fn params() -> LoRaParams {
    LoRaParams {
        spreading_factor: 8,
        bandwidth_hz: 125_000,
        coding_rate: CodingRate::Cr45,
        frequency_hz: 915_000_000,
        tx_power_dbm: 7,
        preamble_syms: 8,
        explicit_header: true,
        crc: true,
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
    let server_port = args.next().unwrap_or_else(|| "COM5".into());
    let reliable_len = args
        .next()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(2_048);
    let serial = SerialPumpConfig {
        turnaround: Duration::from_millis(800),
        ..SerialPumpConfig::default()
    };
    let mut client_radio = RNodeSerialLink::open(
        &client_port,
        params(),
        AirtimeBudget::new(60_000, 60_000),
        serial.clone(),
    )?;
    let mut server_radio = RNodeSerialLink::open(
        &server_port,
        params(),
        AirtimeBudget::new(60_000, 60_000),
        serial,
    )?;
    let client_fw =
        tokio::time::timeout(Duration::from_secs(25), client_radio.wait_online()).await??;
    let server_fw =
        tokio::time::timeout(Duration::from_secs(25), server_radio.wait_online()).await??;
    println!("radios online: {client_port}={client_fw:?}, {server_port}={server_fw:?}");

    let client_id = PrivateIdentity::from_secret_bytes(&[0x11; 64]);
    let server_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let client = Endpoint::new(client_id);
    let server = Arc::new(Endpoint::new(server_id.clone()));
    client.set_reliable_initial_rtt(Duration::from_secs(5));
    server.set_reliable_initial_rtt(Duration::from_secs(5));
    client.set_reliable_max_window(1);
    server.set_reliable_max_window(1);
    client.set_link_mtu(255);
    server.set_link_mtu(255);
    let client_driver = tokio::spawn(drive(
        client.attach_interface(),
        TraceRadio::new("client", client_radio),
    ));
    let server_driver = tokio::spawn(drive(
        server.attach_interface(),
        TraceRadio::new("server", server_radio),
    ));

    let reliable_name = DestinationName::new("retinue", ["headed-reliable"]);
    let reliable_destination = reliable_name.destination_hash(server_id.public());
    server.register_reliable(reliable_name, b"two RNodes");
    let reliable_announce =
        tokio::time::timeout(Duration::from_secs(20), client.next_announcement()).await??;
    if reliable_announce.destination != reliable_destination {
        return Err("received the wrong reliable destination announce".into());
    }
    println!("discovery: reliable destination announced over RF");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reliable_payload = payload(reliable_len, 0x5252_0001);
    let expected_reliable = reliable_payload.clone();
    let reliable_server = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut stream = server.accept_reliable().await?;
            println!("reliable server: accepted");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await?;
            println!("reliable server: received {} bytes and EOF", received.len());
            stream.write_all(b"reliable receipt").await?;
            stream.shutdown().await?;
            Ok::<_, std::io::Error>(received)
        }
    });
    let mut stream = tokio::time::timeout(
        Duration::from_secs(30),
        client.open_reliable(reliable_destination, *server_id.public()),
    )
    .await??;
    println!("reliable: link established");
    stream.write_all(&reliable_payload).await?;
    stream.shutdown().await?;
    println!("reliable: request queued");
    let mut receipt = Vec::new();
    // A multi-frame stream needs several half-duplex data/proof turns. Keep the
    // acceptance deadline above the channel's RF retransmit horizon rather than
    // reusing the one-link-setup deadline.
    tokio::time::timeout(Duration::from_secs(120), stream.read_to_end(&mut receipt)).await??;
    let reliable_received = reliable_server.await??;
    if reliable_received != expected_reliable || receipt != b"reliable receipt" {
        return Err("reliable exchange was not byte-exact".into());
    }
    println!("reliable: {reliable_len}-byte request and receipt passed");

    // Let the reliable link's final proofs and close packet clear both serial
    // queues before broadcasting the next destination announce.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let resource_name = DestinationName::new("retinue", ["headed-resource"]);
    let resource_destination = resource_name.destination_hash(server_id.public());
    server.register_resource(resource_name.clone(), b"two RNodes");
    let mut resource_announce = None;
    for attempt in 0..3 {
        if attempt > 0 {
            server.announce(&resource_name, b"two RNodes");
        }
        match tokio::time::timeout(Duration::from_secs(20), client.next_announcement()).await {
            Ok(Ok(announce)) => {
                resource_announce = Some(announce);
                break;
            }
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => eprintln!("resource announce attempt {} timed out", attempt + 1),
        }
    }
    let resource_announce = resource_announce.ok_or("resource announce did not cross RF")?;
    if resource_announce.destination != resource_destination {
        return Err("received the wrong resource destination announce".into());
    }
    println!("discovery: resource destination announced over RF");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let resource_payload = payload(4_096, 0x5252_0002);
    let expected_resource = resource_payload.clone();
    let resource_config = ResourceTransferConfig {
        timeout: Duration::from_secs(120),
        retry_interval: Duration::from_secs(5),
        request_window: 1,
    };
    let resource_server = tokio::spawn({
        let server = Arc::clone(&server);
        async move {
            let mut accepted = server.accept_resource().await?;
            accepted.session.set_config(resource_config);
            accepted.session.fetch().await
        }
    });
    tokio::time::timeout(
        Duration::from_secs(150),
        client.publish_resource_with_config(
            resource_destination,
            *server_id.public(),
            &resource_payload,
            resource_config,
        ),
    )
    .await??;
    let resource_received =
        tokio::time::timeout(Duration::from_secs(15), resource_server).await???;
    if resource_received != expected_resource {
        return Err("resource transfer was not byte-exact".into());
    }
    println!("resource: 4096-byte publish/fetch passed");

    client_driver.abort();
    server_driver.abort();
    println!("RETINUE TULLE HEADED PASSED");
    Ok(())
}
