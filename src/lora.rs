//! LoRa PHY parameters and time-on-air.
//!
//! Time-on-air (airtime) is what the shared duty-cycle gate ([`crate::airtime`]) debits, so it
//! lives here as a pure function of the modulation parameters. The formula is Semtech's
//! (AN1200.13 / SX1276 datasheet 4.1.1.7):
//!
//! ```text
//! T_sym       = 2^SF / BW
//! T_preamble  = (n_preamble + 4.25) * T_sym
//! symbols     = 8 + max(0, ceil((8*PL - 4*SF + 28 + 16*CRC - 20*IH) / (4*(SF - 2*DE))) * (CR + 4))
//! T_payload   = symbols * T_sym
//! ToA         = T_preamble + T_payload
//! ```
//!
//! where `CR` is 1..=4 (4/5..4/8), `IH` is 1 for an implicit header, `CRC` is 1 when on, and
//! `DE` (low-data-rate optimization) is forced on when the symbol time exceeds 16 ms. `DE` is
//! derived, never stored: storing it invites a transmitter/receiver mismatch.

use core::time::Duration;

/// LoRa coding rate, `4/(4+n)`. The wire encoding is `1..=4`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodingRate {
    /// 4/5
    Cr45,
    /// 4/6
    Cr46,
    /// 4/7
    Cr47,
    /// 4/8
    Cr48,
}

impl CodingRate {
    /// The `CR` term in the airtime formula (1..=4).
    fn value(self) -> i64 {
        match self {
            CodingRate::Cr45 => 1,
            CodingRate::Cr46 => 2,
            CodingRate::Cr47 => 3,
            CodingRate::Cr48 => 4,
        }
    }
}

/// The modulation parameters for a LoRa transmission, enough to compute airtime and to key a
/// duty-cycle budget by channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoRaParams {
    /// Spreading factor, 7..=12.
    pub spreading_factor: u8,
    /// Bandwidth in Hz, e.g. 125_000, 250_000, 500_000.
    pub bandwidth_hz: u32,
    pub coding_rate: CodingRate,
    /// Carrier frequency in Hz (channel identity; not used by the airtime math).
    pub frequency_hz: u32,
    /// Transmit power in dBm. Capped in code to the certified envelope by policy (the
    /// region-lock posture); not used by the airtime math.
    pub tx_power_dbm: u8,
    /// Preamble length in symbols (default 8).
    pub preamble_syms: u16,
    /// Explicit header present (`false` = implicit header, `IH = 1`).
    pub explicit_header: bool,
    /// Payload CRC enabled.
    pub crc: bool,
}

impl LoRaParams {
    /// The symbol time `T_sym = 2^SF / BW`.
    pub fn symbol_time(&self) -> Duration {
        Duration::from_secs_f64((1u64 << self.spreading_factor) as f64 / self.bandwidth_hz as f64)
    }

    /// Whether low-data-rate optimization applies: symbol time greater than 16 ms (SF11/SF12 at
    /// 125 kHz, SF12 at 250 kHz). Derived, per Semtech, never configured.
    pub fn low_data_rate_optimize(&self) -> bool {
        self.symbol_time() > Duration::from_micros(16_000)
    }

    /// The number of payload symbols for a `payload_len`-byte PHY frame.
    pub fn payload_symbols(&self, payload_len: usize) -> u32 {
        let sf = self.spreading_factor as i64;
        let pl = payload_len as i64;
        let crc = if self.crc { 1 } else { 0 };
        let ih = if self.explicit_header { 0 } else { 1 };
        let de = if self.low_data_rate_optimize() { 1 } else { 0 };

        let num = 8 * pl - 4 * sf + 28 + 16 * crc - 20 * ih;
        let den = 4 * (sf - 2 * de); // > 0 for SF >= 7
        // Ceiling division for a signed numerator over a positive denominator: round up for a
        // positive numerator; Rust's truncation-toward-zero already ceils a non-positive one.
        let ceil = if num > 0 {
            (num + den - 1) / den
        } else {
            num / den
        };
        let term = (ceil * (self.coding_rate.value() + 4)).max(0);
        (8 + term) as u32
    }

    /// The full time-on-air for a `payload_len`-byte PHY frame.
    pub fn time_on_air(&self, payload_len: usize) -> Duration {
        let t_sym = (1u64 << self.spreading_factor) as f64 / self.bandwidth_hz as f64;
        let t_preamble = (self.preamble_syms as f64 + 4.25) * t_sym;
        let t_payload = self.payload_symbols(payload_len) as f64 * t_sym;
        Duration::from_secs_f64(t_preamble + t_payload)
    }

    /// Time-on-air in whole milliseconds (rounded), for feeding [`crate::airtime::AirtimeBudget`].
    pub fn time_on_air_ms(&self, payload_len: usize) -> u64 {
        self.time_on_air(payload_len).as_secs_f64().mul_add(1000.0, 0.5) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(sf: u8, bw: u32) -> LoRaParams {
        LoRaParams {
            spreading_factor: sf,
            bandwidth_hz: bw,
            coding_rate: CodingRate::Cr45,
            frequency_hz: 915_000_000,
            tx_power_dbm: 7,
            preamble_syms: 8,
            explicit_header: true,
            crc: true,
        }
    }

    /// Reference vectors from Semtech AN1200.13 / the SX1276 datasheet, as tabulated by the
    /// avbentem and aestechno airtime calculators. Preamble 8, explicit header, CRC on, CR 4/5.
    /// `(SF, BW, PL) -> expected ToA ms`. Includes SF7/BW125 and the SF12/BW125 DE=1 cases.
    #[test]
    fn time_on_air_matches_semtech_reference_vectors() {
        let vectors: &[(u8, u32, usize, f64)] = &[
            (7, 125_000, 12, 41.216),
            (7, 125_000, 20, 56.576),
            (7, 125_000, 64, 118.016),
            (9, 125_000, 20, 185.344),
            (10, 125_000, 20, 370.688),
            (11, 125_000, 20, 741.376),
            (12, 125_000, 12, 1155.072),
            (12, 125_000, 20, 1318.912),
            (12, 125_000, 51, 2465.792),
            (7, 250_000, 20, 28.288),
            (7, 500_000, 20, 14.144),
            (12, 500_000, 20, 329.728),
        ];
        for &(sf, bw, pl, expected_ms) in vectors {
            let got = params(sf, bw).time_on_air(pl).as_secs_f64() * 1000.0;
            assert!(
                (got - expected_ms).abs() < 0.01,
                "SF{sf} BW{bw} PL{pl}: got {got:.3} ms, expected {expected_ms:.3} ms",
            );
        }
    }

    #[test]
    fn low_data_rate_optimize_threshold() {
        // > 16 ms symbol time: SF11/SF12 at 125k, SF12 at 250k, nothing at 500k.
        assert!(!params(10, 125_000).low_data_rate_optimize());
        assert!(params(11, 125_000).low_data_rate_optimize());
        assert!(params(12, 125_000).low_data_rate_optimize());
        assert!(!params(11, 250_000).low_data_rate_optimize());
        assert!(params(12, 250_000).low_data_rate_optimize());
        assert!(!params(12, 500_000).low_data_rate_optimize());
    }

    #[test]
    fn symbol_time_is_two_pow_sf_over_bw() {
        // SF7 @ 125 kHz = 128/125000 = 1.024 ms.
        assert!((params(7, 125_000).symbol_time().as_secs_f64() - 0.001_024).abs() < 1e-9);
    }

    #[test]
    fn time_on_air_ms_rounds() {
        // 118.016 ms -> 118.
        assert_eq!(params(7, 125_000).time_on_air_ms(64), 118);
    }
}
