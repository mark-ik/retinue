//! Two-board acceptance for Tulle's async serial pump.
//!
//! Both RNodes use the same RF parameters. The harness sends a unique raw frame in each
//! direction and requires byte-exact reception before succeeding.
//!
//! Usage: `cargo run --features serial-async --example rnode_roundtrip -- COM5 COM6`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tulle::airtime::AirtimeBudget;
use tulle::link::Received;
use tulle::lora::{CodingRate, LoRaParams};
use tulle::serial::{RNodeSerialLink, SerialPumpConfig};

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

async fn require_frame(
    radio: &mut RNodeSerialLink,
    expected: &[u8],
) -> Result<Received, Box<dyn std::error::Error>> {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let received = radio.recv().await.ok_or("radio receive channel closed")?;
            if received.frame == expected {
                return Ok::<_, Box<dyn std::error::Error>>(received);
            }
            eprintln!("ignoring unrelated {}-byte frame", received.frame.len());
        }
    })
    .await?
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let left_port = args.next().unwrap_or_else(|| "COM5".into());
    let right_port = args.next().unwrap_or_else(|| "COM6".into());
    let config = SerialPumpConfig::default();

    println!("opening {left_port} and {right_port}");
    let mut left = RNodeSerialLink::open(
        &left_port,
        params(),
        AirtimeBudget::new(60_000, 1000),
        config.clone(),
    )?;
    let mut right = RNodeSerialLink::open(
        &right_port,
        params(),
        AirtimeBudget::new(60_000, 1000),
        config,
    )?;

    let left_fw = tokio::time::timeout(Duration::from_secs(25), left.wait_online()).await??;
    let right_fw = tokio::time::timeout(Duration::from_secs(25), right.wait_online()).await??;
    println!("both online: {left_port}={left_fw:?}, {right_port}={right_fw:?}");

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let outbound = format!("tulle:{left_port}>{right_port}:{nonce}").into_bytes();
    let airtime = left.send(outbound.clone()).await?;
    let received = require_frame(&mut right, &outbound).await?;
    println!(
        "{left_port} -> {right_port}: {} bytes, airtime={airtime:?}, RSSI={} dBm, SNR={} dB",
        received.frame.len(),
        received.rssi_dbm,
        received.snr_db
    );

    let reply = format!("tulle:{right_port}>{left_port}:{nonce}").into_bytes();
    let airtime = right.send(reply.clone()).await?;
    let received = require_frame(&mut left, &reply).await?;
    println!(
        "{right_port} -> {left_port}: {} bytes, airtime={airtime:?}, RSSI={} dBm, SNR={} dB",
        received.frame.len(),
        received.rssi_dbm,
        received.snr_db
    );

    left.shutdown().await?;
    right.shutdown().await?;
    println!("ROUND TRIP PASSED: async pump moved byte-exact frames over real RF");
    Ok(())
}
