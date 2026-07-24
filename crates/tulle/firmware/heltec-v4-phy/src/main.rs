#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;
use esp_backtrace as _;
use esp_hal::gpio::{Input, InputConfig, Level, Output, OutputConfig};
use esp_hal::interrupt::software::SoftwareInterruptControl;
use esp_hal::spi::{
    Mode,
    master::{Config as SpiConfig, Spi},
};
use esp_hal::time::Rate;
use esp_hal::timer::timg::TimerGroup;
use esp_hal::usb_serial_jtag::{UsbSerialJtag, UsbSerialJtagRx, UsbSerialJtagTx};
use esp_hal::{Async, Config};
use lora_modulation::{Bandwidth, CodingRate, SpreadingFactor};
use lora_phy::iv::GenericSx126xInterfaceVariant;
use lora_phy::sx126x::{Config as Sx126xConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
use lora_phy::{LoRa, RxMode};
use tulle_phy_profile::{
    CMD_CONFIG, CMD_TX, CONFIG_COMMAND_LEN, EVENT_CONFIG, EVENT_RX, EVENT_TX, MESHTASTIC_SYNC_WORD,
    decode_config_command,
};

esp_bootloader_esp_idf::esp_app_desc!();

const FREQUENCY_HZ: u32 = 906_875_000;
const TX_POWER_DBM: i32 = 17;
const MAX_RADIO_FRAME: usize = 255;

fn spreading_factor(value: u8) -> Option<SpreadingFactor> {
    Some(match value {
        5 => SpreadingFactor::_5,
        6 => SpreadingFactor::_6,
        7 => SpreadingFactor::_7,
        8 => SpreadingFactor::_8,
        9 => SpreadingFactor::_9,
        10 => SpreadingFactor::_10,
        11 => SpreadingFactor::_11,
        12 => SpreadingFactor::_12,
        _ => return None,
    })
}

fn bandwidth(value: u32) -> Option<Bandwidth> {
    Some(match value {
        7_810 => Bandwidth::_7KHz,
        10_420 => Bandwidth::_10KHz,
        15_630 => Bandwidth::_15KHz,
        20_830 => Bandwidth::_20KHz,
        31_250 => Bandwidth::_31KHz,
        41_670 => Bandwidth::_41KHz,
        62_500 => Bandwidth::_62KHz,
        125_000 => Bandwidth::_125KHz,
        250_000 => Bandwidth::_250KHz,
        500_000 => Bandwidth::_500KHz,
        _ => return None,
    })
}

fn coding_rate(value: u8) -> Option<CodingRate> {
    Some(match value {
        5 => CodingRate::_4_5,
        6 => CodingRate::_4_6,
        7 => CodingRate::_4_7,
        8 => CodingRate::_4_8,
        _ => return None,
    })
}

async fn write_all(tx: &mut UsbSerialJtagTx<'static, Async>, bytes: &[u8]) -> bool {
    embedded_io_async::Write::write_all(tx, bytes).await.is_ok()
        && embedded_io_async::Write::flush(tx).await.is_ok()
}

async fn serve_status_only(
    mut rx: UsbSerialJtagRx<'static, Async>,
    mut tx: UsbSerialJtagTx<'static, Async>,
    status: &'static [u8],
) -> ! {
    let _ = write_all(&mut tx, status).await;
    let mut buffer = [0_u8; 64];
    loop {
        match embedded_io_async::Read::read(&mut rx, &mut buffer).await {
            Ok(length) if length > 0 => {
                let reply = if &buffer[..length] == b"sync\n" || &buffer[..length] == b"sync\r\n" {
                    b"2b 24b4\r\n".as_slice()
                } else {
                    status
                };
                let _ = write_all(&mut tx, reply).await;
            }
            _ => {}
        }
    }
}

#[esp_rtos::main]
async fn main(_spawner: Spawner) {
    let peripherals = esp_hal::init(Config::default());

    let sw_int = SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);
    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timg0.timer0, sw_int.software_interrupt0);

    let (mut usb_rx, mut usb_tx) = UsbSerialJtag::new(peripherals.USB_DEVICE)
        .into_async()
        .split();

    let spi = Spi::new(
        peripherals.SPI2,
        SpiConfig::default()
            .with_frequency(Rate::from_mhz(1))
            .with_mode(Mode::_0),
    )
    .unwrap()
    .with_sck(peripherals.GPIO9)
    .with_mosi(peripherals.GPIO10)
    .with_miso(peripherals.GPIO11)
    .into_async();
    let cs = Output::new(peripherals.GPIO8, Level::High, OutputConfig::default());
    let spi = ExclusiveDevice::new(spi, cs, Delay).unwrap();

    let reset = Output::new(peripherals.GPIO12, Level::High, OutputConfig::default());
    let busy = Input::new(peripherals.GPIO13, InputConfig::default());
    let dio1 = Input::new(peripherals.GPIO14, InputConfig::default());
    let interface = GenericSx126xInterfaceVariant::new(reset, dio1, busy, None, None).unwrap();
    let radio = Sx126x::new(
        spi,
        interface,
        Sx126xConfig {
            chip: Sx1262,
            tcxo_ctrl: Some(TcxoCtrlVoltage::Ctrl1V8),
            use_dcdc: true,
            rx_boost: true,
        },
    );
    let mut lora = match LoRa::new_with_sync_word(radio, MESHTASTIC_SYNC_WORD, Delay).await {
        Ok(lora) => lora,
        Err(_) => {
            serve_status_only(
                usb_rx,
                usb_tx,
                b"tulle/heltec-v4 phy online; sx1262 init failed\r\n",
            )
            .await
        }
    };

    let mut modulation = match lora.create_modulation_params(
        SpreadingFactor::_11,
        Bandwidth::_250KHz,
        CodingRate::_4_5,
        FREQUENCY_HZ,
    ) {
        Ok(params) => params,
        Err(_) => {
            serve_status_only(
                usb_rx,
                usb_tx,
                b"tulle/heltec-v4 phy modulation invalid\r\n",
            )
            .await
        }
    };
    let mut tx_params = match lora.create_tx_packet_params(16, false, true, false, &modulation) {
        Ok(params) => params,
        Err(_) => {
            serve_status_only(
                usb_rx,
                usb_tx,
                b"tulle/heltec-v4 phy tx parameters invalid\r\n",
            )
            .await
        }
    };
    let mut rx_params = match lora.create_rx_packet_params(16, false, 255, true, false, &modulation)
    {
        Ok(params) => params,
        Err(_) => {
            serve_status_only(
                usb_rx,
                usb_tx,
                b"tulle/heltec-v4 phy rx parameters invalid\r\n",
            )
            .await
        }
    };

    let online =
        b"tulle/heltec-v4 phy online; sx1262 online; sync=2b reg=24b4; longfast=906875000\r\n";
    let _ = write_all(&mut usb_tx, online).await;
    let mut usb_command = [0_u8; 3 + MAX_RADIO_FRAME];
    let mut usb_command_len = 0_usize;
    let mut prepare_rx = true;
    let mut tx_power_dbm = TX_POWER_DBM;

    loop {
        if prepare_rx {
            if lora
                .prepare_for_rx(RxMode::Continuous, &modulation, &rx_params)
                .await
                .is_err()
            {
                let _ = write_all(&mut usb_tx, b"radio rx setup failed\r\n").await;
                continue;
            }
            prepare_rx = false;
        }

        let mut usb_packet = [0_u8; 64];
        let mut radio_frame = [0_u8; MAX_RADIO_FRAME];
        match select(
            embedded_io_async::Read::read(&mut usb_rx, &mut usb_packet),
            lora.rx(&rx_params, &mut radio_frame),
        )
        .await
        {
            Either::Second(Ok((length, packet_status))) => {
                let length = usize::from(length);
                let mut event = [0_u8; 7 + MAX_RADIO_FRAME];
                event[0] = EVENT_RX;
                event[1..3].copy_from_slice(&(length as u16).to_le_bytes());
                event[3..5].copy_from_slice(&packet_status.rssi.to_le_bytes());
                event[5..7].copy_from_slice(&packet_status.snr.to_le_bytes());
                event[7..7 + length].copy_from_slice(&radio_frame[..length]);
                let _ = write_all(&mut usb_tx, &event[..7 + length]).await;
            }
            Either::Second(Err(_)) => {
                let _ = write_all(&mut usb_tx, b"radio rx failed\r\n").await;
                prepare_rx = true;
            }
            Either::First(Err(_)) => {}
            Either::First(Ok(0)) => {}
            Either::First(Ok(length)) => {
                let packet = &usb_packet[..length];
                if packet == b"status\n" || packet == b"status\r\n" {
                    let _ = write_all(&mut usb_tx, online).await;
                    continue;
                }
                if packet == b"sync\n" || packet == b"sync\r\n" {
                    let _ = write_all(&mut usb_tx, b"2b 24b4\r\n").await;
                    continue;
                }

                if usb_command_len + length > usb_command.len() {
                    usb_command_len = 0;
                    let _ = write_all(&mut usb_tx, &[EVENT_TX, 2, 0, 0]).await;
                    continue;
                }
                usb_command[usb_command_len..usb_command_len + length].copy_from_slice(packet);
                usb_command_len += length;

                let command_len = match usb_command.first().copied() {
                    Some(CMD_TX) if usb_command_len >= 3 => {
                        3 + usize::from(u16::from_le_bytes([usb_command[1], usb_command[2]]))
                    }
                    Some(CMD_CONFIG) => CONFIG_COMMAND_LEN,
                    Some(_) if usb_command_len >= 1 => {
                        usb_command_len = 0;
                        let _ = write_all(&mut usb_tx, &[EVENT_TX, 3, 0, 0]).await;
                        continue;
                    }
                    _ => continue,
                };
                if usb_command_len < command_len {
                    continue;
                }

                if usb_command[0] == CMD_CONFIG {
                    let result = match decode_config_command(&usb_command[..CONFIG_COMMAND_LEN]) {
                        Ok(profile) => {
                            let radio_params = spreading_factor(profile.spreading_factor)
                                .zip(bandwidth(profile.bandwidth_hz))
                                .zip(coding_rate(profile.coding_rate_denominator));
                            match radio_params {
                                Some(((sf, bw), cr)) => {
                                    match lora.create_modulation_params(
                                        sf,
                                        bw,
                                        cr,
                                        profile.frequency_hz,
                                    ) {
                                        Ok(new_modulation) => {
                                            let new_tx = lora.create_tx_packet_params(
                                                profile.preamble_symbols,
                                                !profile.explicit_header,
                                                profile.crc,
                                                profile.invert_iq,
                                                &new_modulation,
                                            );
                                            let new_rx = lora.create_rx_packet_params(
                                                profile.preamble_symbols,
                                                !profile.explicit_header,
                                                255,
                                                profile.crc,
                                                profile.invert_iq,
                                                &new_modulation,
                                            );
                                            match (new_tx, new_rx) {
                                                (Ok(new_tx), Ok(new_rx)) => {
                                                    if lora
                                                        .set_sync_word(profile.sync_word)
                                                        .await
                                                        .is_ok()
                                                    {
                                                        modulation = new_modulation;
                                                        tx_params = new_tx;
                                                        rx_params = new_rx;
                                                        tx_power_dbm =
                                                            i32::from(profile.tx_power_dbm);
                                                        prepare_rx = true;
                                                        0
                                                    } else {
                                                        3
                                                    }
                                                }
                                                _ => 2,
                                            }
                                        }
                                        Err(_) => 2,
                                    }
                                }
                                None => 2,
                            }
                        }
                        Err(_) => 1,
                    };
                    usb_command_len = 0;
                    let _ = write_all(&mut usb_tx, &[EVENT_CONFIG, result]).await;
                    continue;
                }

                let frame_len = command_len - 3;
                if frame_len > MAX_RADIO_FRAME {
                    usb_command_len = 0;
                    let _ = write_all(&mut usb_tx, &[EVENT_TX, 4, 0, 0]).await;
                    continue;
                }

                let sent_len = frame_len as u16;
                let result = if lora
                    .prepare_for_tx(
                        &modulation,
                        &mut tx_params,
                        tx_power_dbm,
                        &usb_command[3..3 + frame_len],
                    )
                    .await
                    .is_ok()
                    && lora.tx().await.is_ok()
                {
                    0
                } else {
                    1
                };
                usb_command_len = 0;
                prepare_rx = true;
                let length_bytes = sent_len.to_le_bytes();
                let _ = write_all(
                    &mut usb_tx,
                    &[EVENT_TX, result, length_bytes[0], length_bytes[1]],
                )
                .await;
            }
        }
    }
}
