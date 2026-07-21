//! The RNode host protocol: a sans-io [`Modem`] over KISS-framed serial commands.
//!
//! Pinned by black-box capture from live hardware (RNode firmware 1.86 on a Heltec T114 and
//! a Heltec V4, driven by RNS 1.3.8; fixtures `rnode_serial_capture.json` and
//! `rnode_rx_capture.json`). The wire, as observed:
//!
//! - Everything is a KISS frame whose first byte is a command.
//! - Init: `DETECT(0x08, 0x73)`, then `FW_VERSION(0x50)`, `PLATFORM(0x48)`, `MCU(0x49)`
//!   probes, then SetHardware: `FREQUENCY(0x01, u32 BE Hz)`, `BANDWIDTH(0x02, u32 BE Hz)`,
//!   `TXPOWER(0x03, dBm)`, `SF(0x04)`, `CR(0x05)`, `RADIO_STATE(0x06, 1)`.
//! - The device echoes each config command as confirmation; a `RADIO_STATE` echo of `01`
//!   means the radio is online, `00` that it refused (e.g. an unverified firmware hash).
//! - TX: `DATA(0x00)` framing the raw packet, KISS-escaped.
//! - RX: per received packet, a triplet: `STAT_RSSI(0x23)` (dBm = raw − 157),
//!   `STAT_SNR(0x24)` (dB = raw as i8 / 4), then `DATA(0x00)` with the packet verbatim.
//! - Unsolicited channel-stat (`0x25`) and battery (`0x27`) frames ride alongside.
//!
//! Sans-io: feed device bytes to [`RNode::on_serial`], write out whatever
//! [`RNode::take_outbound`] returns, drain events via [`Modem::poll`]. The pump owns the
//! serial port and the clock.

use std::collections::VecDeque;

use crate::kiss;
use crate::lora::LoRaParams;
use crate::modem::{Modem, ModemError, ModemEvent};

/// KISS command bytes, observed on the wire and named per the public constant table.
pub mod cmd {
    pub const DATA: u8 = 0x00;
    pub const FREQUENCY: u8 = 0x01;
    pub const BANDWIDTH: u8 = 0x02;
    pub const TXPOWER: u8 = 0x03;
    pub const SF: u8 = 0x04;
    pub const CR: u8 = 0x05;
    pub const RADIO_STATE: u8 = 0x06;
    pub const DETECT: u8 = 0x08;
    pub const STAT_RSSI: u8 = 0x23;
    pub const STAT_SNR: u8 = 0x24;
    pub const STAT_CHTM: u8 = 0x25;
    pub const STAT_BAT: u8 = 0x27;
    pub const PLATFORM: u8 = 0x48;
    pub const MCU: u8 = 0x49;
    pub const FW_VERSION: u8 = 0x50;
    pub const ERROR: u8 = 0x90;
}

/// Detect request/response magic bytes.
pub const DETECT_REQ: u8 = 0x73;
pub const DETECT_RESP: u8 = 0x46;

/// RSSI on the wire is offset by this: `dBm = raw - 157`.
pub const RSSI_OFFSET: i16 = 157;

/// Largest frame the host protocol carries (RNS's packet MTU). The LoRa PHY caps a single
/// transmission near 255 bytes; how the firmware treats larger frames is not yet pinned by
/// capture (ours are ≤172 bytes), so treat >255 as unproven rather than safe.
pub const MAX_FRAME: usize = 500;

/// A sans-io RNode: implements [`Modem`] on top of the captured host protocol.
pub struct RNode {
    params: LoRaParams,
    deframer: kiss::Deframer,
    outbound: Vec<u8>,
    events: VecDeque<ModemEvent>,
    detected: bool,
    online: bool,
    fw_version: Option<(u8, u8)>,
    /// Stats arriving ahead of their data frame (the RX triplet).
    pending_rssi: Option<i16>,
    pending_snr: Option<f32>,
    /// Last device-reported error command payload, if any.
    last_error: Option<Vec<u8>>,
}

impl RNode {
    pub fn new(params: LoRaParams) -> Self {
        RNode {
            params,
            deframer: kiss::Deframer::new(MAX_FRAME + 8),
            outbound: Vec::new(),
            events: VecDeque::new(),
            detected: false,
            online: false,
            fw_version: None,
            pending_rssi: None,
            pending_snr: None,
            last_error: None,
        }
    }

    fn queue_cmd(&mut self, command: u8, payload: &[u8]) {
        let mut frame = Vec::with_capacity(1 + payload.len());
        frame.push(command);
        frame.extend_from_slice(payload);
        self.outbound.extend_from_slice(&kiss::encode(&frame));
    }

    /// Queue the whole init conversation: detect, probes, SetHardware, radio on. Mirrors the
    /// captured RNS sequence frame for frame.
    pub fn start(&mut self) {
        self.queue_cmd(cmd::DETECT, &[DETECT_REQ]);
        self.queue_cmd(cmd::FW_VERSION, &[0x00]);
        self.queue_cmd(cmd::PLATFORM, &[0x00]);
        self.queue_cmd(cmd::MCU, &[0x00]);
        self.queue_config();
    }

    fn queue_config(&mut self) {
        let p = self.params;
        self.queue_cmd(cmd::FREQUENCY, &p.frequency_hz.to_be_bytes());
        self.queue_cmd(cmd::BANDWIDTH, &p.bandwidth_hz.to_be_bytes());
        self.queue_cmd(cmd::TXPOWER, &[p.tx_power_dbm]);
        self.queue_cmd(cmd::SF, &[p.spreading_factor]);
        self.queue_cmd(cmd::CR, &[coding_rate_wire(p)]);
        self.queue_cmd(cmd::RADIO_STATE, &[0x01]);
    }

    /// Bytes waiting to be written to the serial port. Empties the queue.
    pub fn take_outbound(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbound)
    }

    /// Feed bytes read from the serial port.
    pub fn on_serial(&mut self, bytes: &[u8]) {
        let mut frames = Vec::new();
        self.deframer.push(bytes, &mut frames);
        for frame in frames {
            self.on_frame(&frame);
        }
    }

    fn on_frame(&mut self, frame: &[u8]) {
        let Some((&command, payload)) = frame.split_first() else {
            return;
        };
        match command {
            cmd::DETECT => {
                if payload.first() == Some(&DETECT_RESP) {
                    self.detected = true;
                }
            }
            cmd::FW_VERSION => {
                if payload.len() >= 2 {
                    self.fw_version = Some((payload[0], payload[1]));
                }
            }
            cmd::RADIO_STATE => {
                let was = self.online;
                self.online = payload.first() == Some(&1);
                if self.online && !was {
                    self.events.push_back(ModemEvent::ChannelClear);
                }
            }
            cmd::STAT_RSSI => {
                if let Some(&raw) = payload.first() {
                    self.pending_rssi = Some(raw as i16 - RSSI_OFFSET);
                }
            }
            cmd::STAT_SNR => {
                if let Some(&raw) = payload.first() {
                    self.pending_snr = Some(raw as i8 as f32 / 4.0);
                }
            }
            cmd::DATA => {
                self.events.push_back(ModemEvent::Received {
                    frame: payload.to_vec(),
                    rssi_dbm: self.pending_rssi.take().unwrap_or(0),
                    snr_db: self.pending_snr.take().unwrap_or(0.0),
                });
            }
            cmd::ERROR => {
                self.last_error = Some(payload.to_vec());
            }
            // Config echoes (frequency/bandwidth/txpower/sf/cr), channel stats, battery,
            // platform/MCU probes: informational, no action needed.
            _ => {}
        }
    }

    /// Whether the device answered the detect probe.
    pub fn is_detected(&self) -> bool {
        self.detected
    }

    /// Whether the radio reported itself online (`RADIO_STATE` echo of 1).
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Firmware version as (major, minor), once probed.
    pub fn fw_version(&self) -> Option<(u8, u8)> {
        self.fw_version
    }

    /// The last `ERROR` frame payload the device sent, if any.
    pub fn last_error(&self) -> Option<&[u8]> {
        self.last_error.as_deref()
    }
}

/// The CR wire value: RNode takes the denominator (5..=8 for 4/5..4/8).
fn coding_rate_wire(p: LoRaParams) -> u8 {
    use crate::lora::CodingRate::*;
    match p.coding_rate {
        Cr45 => 5,
        Cr46 => 6,
        Cr47 => 7,
        Cr48 => 8,
    }
}

impl Modem for RNode {
    fn params(&self) -> LoRaParams {
        self.params
    }

    fn set_params(&mut self, params: LoRaParams) -> Result<(), ModemError> {
        self.params = params;
        self.queue_config();
        Ok(())
    }

    fn max_frame_len(&self) -> usize {
        MAX_FRAME
    }

    fn enqueue(&mut self, frame: &[u8]) -> Result<core::time::Duration, ModemError> {
        if frame.len() > MAX_FRAME {
            return Err(ModemError::TooLong { max: MAX_FRAME });
        }
        if !self.online {
            return Err(ModemError::Busy);
        }
        let mut f = Vec::with_capacity(1 + frame.len());
        f.push(cmd::DATA);
        f.extend_from_slice(frame);
        self.outbound.extend_from_slice(&kiss::encode(&f));
        Ok(self.params.time_on_air(frame.len()))
    }

    fn poll(&mut self) -> Option<ModemEvent> {
        self.events.pop_front()
    }
}
