#![no_std]

/// Meshtastic's documented LoRa synchronization byte.
pub const MESHTASTIC_SYNC_WORD: u8 = 0x2b;
/// MeshCore's private-network LoRa synchronization byte.
pub const MESHCORE_SYNC_WORD: u8 = 0x12;

/// Direct-PHY host-to-firmware command markers.
pub const CMD_TX: u8 = 0x01;
pub const CMD_CONFIG: u8 = 0x02;

/// Direct-PHY firmware-to-host event markers.
pub const EVENT_RX: u8 = 0x81;
pub const EVENT_TX: u8 = 0x82;
pub const EVENT_CONFIG: u8 = 0x83;
/// Firmware-to-host SX126x diagnostic event marker.
pub const EVENT_DIAGNOSTIC: u8 = 0x84;

/// Bytes in a complete [`CMD_CONFIG`] command.
pub const CONFIG_COMMAND_LEN: usize = 16;

/// Radio parameters that are independent of a particular HAL or driver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhyProfile {
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate_denominator: u8,
    pub preamble_symbols: u16,
    pub sync_word: u8,
    pub explicit_header: bool,
    pub crc: bool,
    pub invert_iq: bool,
    pub tx_power_dbm: i8,
}

impl PhyProfile {
    /// Meshtastic LongFast modulation with a caller-selected regional frequency.
    pub const fn meshtastic_long_fast(frequency_hz: u32) -> Self {
        Self {
            frequency_hz,
            bandwidth_hz: 250_000,
            spreading_factor: 11,
            coding_rate_denominator: 5,
            preamble_symbols: 16,
            sync_word: MESHTASTIC_SYNC_WORD,
            explicit_header: true,
            crc: true,
            invert_iq: false,
            tx_power_dbm: 17,
        }
    }

    /// MeshCore modulation with caller-selected companion radio parameters.
    ///
    /// MeshCore lengthens the preamble to 32 symbols at SF5 through SF8 and
    /// otherwise uses 16. Frequency, bandwidth, spreading factor, and coding
    /// rate remain network settings rather than board defaults.
    pub const fn meshcore(
        frequency_hz: u32,
        bandwidth_hz: u32,
        spreading_factor: u8,
        coding_rate_denominator: u8,
    ) -> Self {
        Self {
            frequency_hz,
            bandwidth_hz,
            spreading_factor,
            coding_rate_denominator,
            preamble_symbols: if spreading_factor <= 8 { 32 } else { 16 },
            sync_word: MESHCORE_SYNC_WORD,
            explicit_header: true,
            crc: true,
            invert_iq: false,
            tx_power_dbm: 17,
        }
    }

    /// Validate the protocol-independent envelope accepted by Tulle firmware.
    pub const fn validate(self) -> Result<Self, ProfileError> {
        if self.frequency_hz == 0 {
            return Err(ProfileError::Frequency);
        }
        if self.bandwidth_hz == 0 {
            return Err(ProfileError::Bandwidth);
        }
        if self.spreading_factor < 5 || self.spreading_factor > 12 {
            return Err(ProfileError::SpreadingFactor);
        }
        if self.coding_rate_denominator < 5 || self.coding_rate_denominator > 8 {
            return Err(ProfileError::CodingRate);
        }
        if self.preamble_symbols == 0 {
            return Err(ProfileError::Preamble);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    Command,
    Length,
    Frequency,
    Bandwidth,
    SpreadingFactor,
    CodingRate,
    Preamble,
}

/// Encode a complete runtime radio-profile command.
pub const fn encode_config_command(
    profile: PhyProfile,
) -> Result<[u8; CONFIG_COMMAND_LEN], ProfileError> {
    let profile = match profile.validate() {
        Ok(profile) => profile,
        Err(error) => return Err(error),
    };
    let mut out = [0_u8; CONFIG_COMMAND_LEN];
    out[0] = CMD_CONFIG;
    let frequency = profile.frequency_hz.to_le_bytes();
    out[1] = frequency[0];
    out[2] = frequency[1];
    out[3] = frequency[2];
    out[4] = frequency[3];
    let bandwidth = profile.bandwidth_hz.to_le_bytes();
    out[5] = bandwidth[0];
    out[6] = bandwidth[1];
    out[7] = bandwidth[2];
    out[8] = bandwidth[3];
    out[9] = profile.spreading_factor;
    out[10] = profile.coding_rate_denominator;
    let preamble = profile.preamble_symbols.to_le_bytes();
    out[11] = preamble[0];
    out[12] = preamble[1];
    out[13] = profile.sync_word;
    out[14] = (profile.explicit_header as u8)
        | ((profile.crc as u8) << 1)
        | ((profile.invert_iq as u8) << 2);
    out[15] = profile.tx_power_dbm as u8;
    Ok(out)
}

/// Decode and validate a complete runtime radio-profile command.
pub fn decode_config_command(command: &[u8]) -> Result<PhyProfile, ProfileError> {
    if command.len() != CONFIG_COMMAND_LEN {
        return Err(ProfileError::Length);
    }
    if command[0] != CMD_CONFIG {
        return Err(ProfileError::Command);
    }
    PhyProfile {
        frequency_hz: u32::from_le_bytes([command[1], command[2], command[3], command[4]]),
        bandwidth_hz: u32::from_le_bytes([command[5], command[6], command[7], command[8]]),
        spreading_factor: command[9],
        coding_rate_denominator: command[10],
        preamble_symbols: u16::from_le_bytes([command[11], command[12]]),
        sync_word: command[13],
        explicit_header: command[14] & 1 != 0,
        crc: command[14] & 2 != 0,
        invert_iq: command[14] & 4 != 0,
        tx_power_dbm: command[15] as i8,
    }
    .validate()
}

/// Convert the canonical one-byte LoRa sync word to the SX126x register form.
pub const fn sx126x_sync_word(sync_word: u8) -> [u8; 2] {
    [(sync_word & 0xf0) | 0x04, ((sync_word & 0x0f) << 4) | 0x04]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_sync_words_have_the_documented_sx126x_encoding() {
        assert_eq!(sx126x_sync_word(0x34), [0x34, 0x44]);
        assert_eq!(sx126x_sync_word(0x12), [0x14, 0x24]);
        assert_eq!(sx126x_sync_word(MESHTASTIC_SYNC_WORD), [0x24, 0xb4]);
    }

    #[test]
    fn long_fast_keeps_frequency_a_board_setting() {
        let profile = PhyProfile::meshtastic_long_fast(906_875_000);
        assert_eq!(profile.frequency_hz, 906_875_000);
        assert_eq!(profile.sync_word, MESHTASTIC_SYNC_WORD);
        assert_eq!(profile.preamble_symbols, 16);
    }

    #[test]
    fn meshcore_profile_tracks_runtime_radio_settings_and_preamble_rule() {
        let slow = PhyProfile::meshcore(915_000_000, 250_000, 10, 5);
        assert_eq!(slow.sync_word, MESHCORE_SYNC_WORD);
        assert_eq!(slow.preamble_symbols, 16);
        assert!(slow.crc);

        let fast = PhyProfile::meshcore(915_000_000, 62_500, 8, 5);
        assert_eq!(fast.preamble_symbols, 32);
    }

    #[test]
    fn runtime_config_round_trips_all_profile_fields() {
        let mut profile = PhyProfile::meshtastic_long_fast(906_875_000);
        profile.sync_word = 0x12;
        profile.invert_iq = true;
        profile.tx_power_dbm = 11;
        let command = encode_config_command(profile).unwrap();
        assert_eq!(command[0], CMD_CONFIG);
        assert_eq!(decode_config_command(&command), Ok(profile));
    }

    #[test]
    fn runtime_config_rejects_invalid_profiles() {
        let mut profile = PhyProfile::meshtastic_long_fast(906_875_000);
        profile.spreading_factor = 13;
        assert_eq!(
            encode_config_command(profile),
            Err(ProfileError::SpreadingFactor)
        );
    }
}
