//! Live smoke test: bring a real RNode online through tulle's driver over serial, and
//! transmit one frame. Proves the sans-io [`RNode`] drives actual hardware in real time, not
//! just against the captured fixtures.
//!
//! Usage: `cargo run --example rnode_smoke -- COM5`

use std::time::{Duration, Instant};

use serial2::SerialPort;
use tulle::lora::{CodingRate, LoRaParams};
use tulle::modem::{Modem, ModemEvent};
use tulle::rnode::RNode;

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

fn main() {
    let port_name = std::env::args().nth(1).unwrap_or_else(|| "COM5".into());
    println!("opening {port_name} at 115200...");
    let mut port = SerialPort::open(&port_name, 115200).expect("open serial port");
    port.set_read_timeout(Duration::from_millis(50)).unwrap();
    // nRF (and many CDC-ACM) devices gate their data on DTR ("terminal present"); pyserial
    // asserts it on open, serial2 does not, so do it explicitly.
    port.set_dtr(true).ok();
    port.set_rts(true).ok();

    // The device may reboot when the port opens; let it settle before probing.
    std::thread::sleep(Duration::from_secs(3));

    // Sanity probe: the device emits unsolicited battery/stat frames; confirm we can read.
    {
        let mut probe = [0u8; 256];
        let mut seen = 0usize;
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if let Ok(n) = port.read(&mut probe) {
                seen += n;
            }
        }
        println!("  (pre-probe: read {seen} unsolicited bytes from the device)");
    }

    let mut rnode = RNode::new(params());
    rnode.start();
    port.write_all(&rnode.take_outbound()).unwrap();

    let mut buf = [0u8; 1024];
    let mut last_retry = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(25);
    while Instant::now() < deadline {
        match port.read(&mut buf) {
            Ok(n) if n > 0 => rnode.on_serial(&buf[..n]),
            _ => {}
        }
        let out = rnode.take_outbound();
        if !out.is_empty() {
            port.write_all(&out).unwrap();
        }
        while let Some(ev) = rnode.poll() {
            if let ModemEvent::Received {
                frame,
                rssi_dbm,
                snr_db,
            } = ev
            {
                println!("  RX {} bytes  rssi={rssi_dbm} dBm  snr={snr_db} dB", frame.len());
            }
        }
        if rnode.is_online() {
            break;
        }
        // RNS re-sends config a few seconds in; do the same if the radio has not come online.
        if last_retry.elapsed() > Duration::from_secs(6) {
            println!("  (re-sending config)");
            rnode.start();
            port.write_all(&rnode.take_outbound()).unwrap();
            last_retry = Instant::now();
        }
    }

    println!(
        "detected={} online={} fw={:?}",
        rnode.is_detected(),
        rnode.is_online(),
        rnode.fw_version()
    );
    if let Some(err) = rnode.last_error() {
        println!("device error frame: {}", hex(err));
    }

    if rnode.is_online() {
        let airtime = rnode.enqueue(b"tulle-live-smoke-test").unwrap();
        port.write_all(&rnode.take_outbound()).unwrap();
        println!("transmitted a test frame (airtime {:?})", airtime);
        // Drain a moment for any TxDone/echo.
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if let Ok(n) = port.read(&mut buf) {
                if n > 0 {
                    rnode.on_serial(&buf[..n]);
                }
            }
        }
        println!("SMOKE TEST PASSED: tulle drove a real RNode online and transmitted.");
    } else {
        println!("SMOKE TEST FAILED: radio did not come online.");
        std::process::exit(1);
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
