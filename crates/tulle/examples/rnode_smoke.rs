//! Bring one real RNode online through Tulle's async serial pump and transmit one frame.
//!
//! Usage: `cargo run --features serial-async --example rnode_smoke -- COM5`

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port = std::env::args().nth(1).unwrap_or_else(|| "COM5".into());
    println!("opening {port} at 115200");
    let mut radio = RNodeSerialLink::open(
        &port,
        params(),
        AirtimeBudget::new(60_000, 1000),
        SerialPumpConfig::default(),
    )?;
    let firmware = tokio::time::timeout(Duration::from_secs(25), radio.wait_online()).await??;
    println!("online, firmware={firmware:?}");

    let airtime = radio.send(b"tulle-async-live-smoke".to_vec()).await?;
    println!("frame written to radio, calculated airtime={airtime:?}");
    radio.shutdown().await?;
    println!("SMOKE TEST PASSED");
    Ok(())
}
