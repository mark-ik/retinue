//! Headed probe for the largest byte-exact RF frame accepted by RNode firmware.
//!
//! Usage: `cargo run --features serial-async --example rnode_mtu -- COM6 COM7`

use std::time::Duration;

use tulle::airtime::AirtimeBudget;
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

fn payload(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(length as u8))
        .collect()
}

async fn receive_exact(radio: &mut RNodeSerialLink, expected: &[u8]) -> bool {
    tokio::time::timeout(Duration::from_secs(4), async {
        while let Some(received) = radio.recv().await {
            if received.frame == expected {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let left_port = args.next().unwrap_or_else(|| "COM6".into());
    let right_port = args.next().unwrap_or_else(|| "COM7".into());
    let config = SerialPumpConfig::default();
    let mut left = RNodeSerialLink::open(
        &left_port,
        params(),
        AirtimeBudget::new(60_000, 60_000),
        config.clone(),
    )?;
    let mut right = RNodeSerialLink::open(
        &right_port,
        params(),
        AirtimeBudget::new(60_000, 60_000),
        config,
    )?;
    let left_fw = tokio::time::timeout(Duration::from_secs(25), left.wait_online()).await??;
    let right_fw = tokio::time::timeout(Duration::from_secs(25), right.wait_online()).await??;
    println!("online: {left_port}={left_fw:?}, {right_port}={right_fw:?}");

    for length in [240, 254, 255, 256, 300, 400, 499, 500, 501] {
        let frame = payload(length);
        match left.send(frame.clone()).await {
            Ok(_) if receive_exact(&mut right, &frame).await => {
                println!("{length}: received exact")
            }
            Ok(_) => println!("{length}: not received"),
            Err(error) => println!("{length}: host rejected: {error}"),
        }
    }

    left.shutdown().await?;
    right.shutdown().await?;
    Ok(())
}
