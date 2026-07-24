#![no_std]
#![no_main]

use core::convert::Infallible;

use embassy_executor::Spawner;
use embassy_futures::select::{Either, select};
use embassy_nrf::config::HfclkSource;
use embassy_nrf::gpio::{Input, Level, Output, OutputDrive, Pull};
use embassy_nrf::usb::Driver;
use embassy_nrf::usb::vbus_detect::HardwareVbusDetect;
use embassy_nrf::{bind_interrupts, peripherals, usb};
use embassy_time::{Delay, Duration, Timer, with_timeout};
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::{Builder, Config, UsbDevice};
use embedded_hal::spi::ErrorType;
use embedded_hal_async::spi::SpiBus;
use embedded_hal_bus::spi::ExclusiveDevice;
use lora_modulation::{Bandwidth, CodingRate, SpreadingFactor};
use lora_phy::mod_params::RadioError;
use lora_phy::mod_traits::InterfaceVariant;
use lora_phy::sx126x::{Config as Sx126xConfig, Sx126x, Sx1262, TcxoCtrlVoltage};
use lora_phy::{LoRa, RxMode};
use panic_halt as _;
use selvage::{
    CMD_CONFIG, CMD_TX, CONFIG_COMMAND_LEN, EVENT_CONFIG, EVENT_DIAGNOSTIC, EVENT_RX, EVENT_TX,
    MESHTASTIC_SYNC_WORD, decode_config_command, sx126x_sync_word,
};
use static_cell::StaticCell;

bind_interrupts!(struct Irqs {
    USBD => usb::InterruptHandler<peripherals::USBD>;
    CLOCK_POWER => usb::vbus_detect::InterruptHandler;
});

type UsbDriver = Driver<'static, HardwareVbusDetect>;

const FREQUENCY_HZ: u32 = 906_875_000;
const TX_POWER_DBM: i32 = 17;
const MAX_RADIO_FRAME: usize = 255;
const USB_PACKET: usize = 64;

struct T114Spi<'d> {
    sck: Output<'d>,
    mosi: Output<'d>,
    miso: Input<'d>,
}

impl T114Spi<'_> {
    fn transfer_byte(&mut self, output: u8) -> u8 {
        let mut input = 0u8;
        for bit in (0..8).rev() {
            if output & (1 << bit) == 0 {
                self.mosi.set_low();
            } else {
                self.mosi.set_high();
            }
            cortex_m::asm::delay(64);
            self.sck.set_high();
            input = (input << 1) | u8::from(self.miso.is_high());
            cortex_m::asm::delay(64);
            self.sck.set_low();
        }
        input
    }
}

impl ErrorType for T114Spi<'_> {
    type Error = Infallible;
}

impl SpiBus<u8> for T114Spi<'_> {
    async fn read(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        for word in words {
            *word = self.transfer_byte(0);
        }
        Ok(())
    }

    async fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
        for &word in words {
            let _ = self.transfer_byte(word);
        }
        Ok(())
    }

    async fn transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), Self::Error> {
        for index in 0..read.len().max(write.len()) {
            let input = self.transfer_byte(write.get(index).copied().unwrap_or(0));
            if let Some(word) = read.get_mut(index) {
                *word = input;
            }
        }
        Ok(())
    }

    async fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        for word in words {
            *word = self.transfer_byte(*word);
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct T114Interface<'d> {
    reset: Output<'d>,
    dio1: Input<'d>,
    busy: Input<'d>,
}

impl InterfaceVariant for T114Interface<'_> {
    async fn reset(&mut self, delay: &mut impl lora_phy::DelayNs) -> Result<(), RadioError> {
        delay.delay_ms(10).await;
        self.reset.set_low();
        delay.delay_ms(20).await;
        self.reset.set_high();
        delay.delay_ms(10).await;
        Ok(())
    }

    async fn wait_on_busy(&mut self) -> Result<(), RadioError> {
        while self.busy.is_high() {
            Timer::after_micros(50).await;
        }
        Ok(())
    }

    async fn await_irq(&mut self) -> Result<(), RadioError> {
        // SX1262 holds DIO1 high until its IRQ flags are cleared. Polling the
        // level avoids depending on GPIO sense wakeups across the T114's
        // SoftDevice bootloader boundary and cannot miss the latched event.
        while self.dio1.is_low() {
            Timer::after_millis(1).await;
        }
        Ok(())
    }

    async fn enable_rf_switch_rx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }

    async fn enable_rf_switch_tx(&mut self) -> Result<(), RadioError> {
        Ok(())
    }

    async fn disable_rf_switch(&mut self) -> Result<(), RadioError> {
        Ok(())
    }
}

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

fn diagnostic_event(irq_status: u16, device_errors: u16, sync_word: [u8; 2]) -> [u8; 7] {
    let irq = irq_status.to_le_bytes();
    let errors = device_errors.to_le_bytes();
    [
        EVENT_DIAGNOSTIC,
        irq[0],
        irq[1],
        errors[0],
        errors[1],
        sync_word[0],
        sync_word[1],
    ]
}

async fn write_all(class: &mut CdcAcmClass<'static, UsbDriver>, bytes: &[u8]) -> bool {
    for chunk in bytes.chunks(USB_PACKET) {
        if class.write_packet(chunk).await.is_err() {
            return false;
        }
    }
    true
}

async fn serve_status_only(mut class: CdcAcmClass<'static, UsbDriver>, status: &'static [u8]) -> ! {
    loop {
        class.wait_connection().await;
        if !write_all(&mut class, status).await {
            continue;
        }
        let mut buffer = [0_u8; USB_PACKET];
        while let Ok(length) = class.read_packet(&mut buffer).await {
            let reply = if &buffer[..length] == b"sync\n" || &buffer[..length] == b"sync\r\n" {
                b"2b 24b4\r\n".as_slice()
            } else {
                status
            };
            if !write_all(&mut class, reply).await {
                break;
            }
        }
    }
}

#[embassy_executor::task]
async fn usb_task(mut device: UsbDevice<'static, UsbDriver>) {
    device.run().await;
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut nrf_config = embassy_nrf::config::Config::default();
    nrf_config.hfclk_source = HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(nrf_config);

    let driver = Driver::new(p.USBD, Irqs, HardwareVbusDetect::new(Irqs));
    let mut usb_config = Config::new(0x1915, 0x521f);
    usb_config.manufacturer = Some("Tulle");
    usb_config.product = Some("T114 direct PHY");
    usb_config.serial_number = Some("TULLE-T114-01");
    usb_config.max_power = 100;
    usb_config.max_packet_size_0 = 64;

    static STATE: StaticCell<State> = StaticCell::new();
    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 128]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
    let mut builder = Builder::new(
        driver,
        usb_config,
        &mut CONFIG_DESC.init([0; 256])[..],
        &mut BOS_DESC.init([0; 256])[..],
        &mut MSOS_DESC.init([0; 128])[..],
        &mut CONTROL_BUF.init([0; 128])[..],
    );
    let mut class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), 64);
    let usb = builder.build();
    match usb_task(usb) {
        Ok(task) => spawner.spawn(task),
        Err(_) => panic!(),
    }

    let spi = T114Spi {
        sck: Output::new(p.P0_19, Level::Low, OutputDrive::Standard),
        mosi: Output::new(p.P0_22, Level::Low, OutputDrive::Standard),
        miso: Input::new(p.P0_23, Pull::None),
    };
    let cs = Output::new(p.P0_24, Level::High, OutputDrive::Standard);
    let spi = match ExclusiveDevice::new(spi, cs, Delay) {
        Ok(spi) => spi,
        Err(_) => panic!(),
    };

    let reset = Output::new(p.P0_25, Level::High, OutputDrive::Standard);
    let dio1 = Input::new(p.P0_20, Pull::None);
    let busy = Input::new(p.P0_17, Pull::None);
    let interface = T114Interface { reset, dio1, busy };
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
    let init = with_timeout(
        Duration::from_secs(3),
        LoRa::new_with_sync_word(radio, MESHTASTIC_SYNC_WORD, Delay),
    )
    .await;
    let mut lora = match init {
        Ok(Ok(lora)) => lora,
        Ok(Err(_)) => {
            serve_status_only(
                class,
                b"tulle/t114 phy online; sx1262 init failed\r\n".as_slice(),
            )
            .await
        }
        Err(_) => {
            serve_status_only(
                class,
                b"tulle/t114 phy online; sx1262 init timed out\r\n".as_slice(),
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
            serve_status_only(class, b"tulle/t114 phy modulation invalid\r\n".as_slice()).await
        }
    };
    let mut tx_params = match lora.create_tx_packet_params(16, false, true, false, &modulation) {
        Ok(params) => params,
        Err(_) => {
            serve_status_only(
                class,
                b"tulle/t114 phy tx parameters invalid\r\n".as_slice(),
            )
            .await
        }
    };
    let mut rx_params = match lora.create_rx_packet_params(16, false, 255, true, false, &modulation)
    {
        Ok(params) => params,
        Err(_) => {
            serve_status_only(
                class,
                b"tulle/t114 phy rx parameters invalid\r\n".as_slice(),
            )
            .await
        }
    };

    let online = b"tulle/t114 phy online; sx1262 online; spi=software; irq=poll; sync=2b reg=24b4; longfast=906875000\r\n";
    let mut usb_command = [0_u8; 3 + MAX_RADIO_FRAME];
    let mut usb_command_len;
    let mut tx_power_dbm = TX_POWER_DBM;

    loop {
        class.wait_connection().await;
        if !write_all(&mut class, online).await {
            continue;
        }
        usb_command_len = 0;
        let mut prepare_rx = true;

        'connected: loop {
            if prepare_rx {
                if lora
                    .prepare_for_rx(RxMode::Continuous, &modulation, &rx_params)
                    .await
                    .is_err()
                {
                    if !write_all(&mut class, b"radio rx setup failed\r\n").await {
                        break;
                    }
                    continue;
                }
                prepare_rx = false;
            }

            let mut usb_packet = [0_u8; USB_PACKET];
            let mut radio_frame = [0_u8; MAX_RADIO_FRAME];
            match select(
                class.read_packet(&mut usb_packet),
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
                    if !write_all(&mut class, &event[..7 + length]).await {
                        break;
                    }
                }
                Either::Second(Err(_)) => {
                    if !write_all(&mut class, b"radio rx failed\r\n").await {
                        break;
                    }
                    prepare_rx = true;
                }
                Either::First(Err(_)) => break,
                Either::First(Ok(length)) => {
                    let packet = &usb_packet[..length];
                    if packet == b"bootloader\n" || packet == b"bootloader\r\n" {
                        let _ = write_all(&mut class, b"entering serial bootloader\r\n").await;
                        Timer::after_millis(20).await;
                        embassy_nrf::pac::POWER
                            .gpregret()
                            .write(|value| value.set_gpregret(0x4e));
                        cortex_m::peripheral::SCB::sys_reset();
                    }
                    if packet == b"status\n" || packet == b"status\r\n" {
                        if !write_all(&mut class, online).await {
                            break;
                        }
                        continue;
                    }
                    if packet == b"sync\n" || packet == b"sync\r\n" {
                        let sync = sx126x_sync_word(MESHTASTIC_SYNC_WORD);
                        let reply = if sync == [0x24, 0xb4] {
                            b"2b 24b4\r\n".as_slice()
                        } else {
                            b"sync encoding fault\r\n".as_slice()
                        };
                        if !write_all(&mut class, reply).await {
                            break;
                        }
                        continue;
                    }
                    if packet == b"radio\n" || packet == b"radio\r\n" {
                        let reply = match lora.sx126x_diagnostics().await {
                            Ok(diagnostics) => diagnostic_event(
                                diagnostics.irq_status,
                                diagnostics.device_errors,
                                diagnostics.sync_word,
                            ),
                            Err(_) => [EVENT_DIAGNOSTIC, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                        };
                        if !write_all(&mut class, &reply).await {
                            break;
                        }
                        continue;
                    }

                    if usb_command_len + length > usb_command.len() {
                        usb_command_len = 0;
                        let reply = [EVENT_TX, 2, 0, 0];
                        if !write_all(&mut class, &reply).await {
                            break;
                        }
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
                            let reply = [EVENT_TX, 3, 0, 0];
                            if !write_all(&mut class, &reply).await {
                                break;
                            }
                            continue;
                        }
                        _ => continue,
                    };
                    if usb_command_len < command_len {
                        continue;
                    }

                    if usb_command[0] == CMD_CONFIG {
                        let result = match decode_config_command(&usb_command[..CONFIG_COMMAND_LEN])
                        {
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
                        if !write_all(&mut class, &[EVENT_CONFIG, result]).await {
                            break;
                        }
                        continue;
                    }

                    let frame_len = command_len - 3;
                    if frame_len > MAX_RADIO_FRAME {
                        usb_command_len = 0;
                        let reply = [EVENT_TX, 4, 0, 0];
                        if !write_all(&mut class, &reply).await {
                            break;
                        }
                        continue;
                    }

                    let sent_len = frame_len as u16;
                    let prepared = lora
                        .prepare_for_tx(
                            &modulation,
                            &mut tx_params,
                            tx_power_dbm,
                            &usb_command[3..3 + frame_len],
                        )
                        .await
                        .is_ok();
                    let result = if !prepared {
                        1
                    } else {
                        match with_timeout(Duration::from_secs(3), lora.tx()).await {
                            Ok(Ok(())) => 0,
                            Ok(Err(_)) => 1,
                            Err(_) => 5,
                        }
                    };
                    if result == 5 {
                        let diagnostic = match lora.sx126x_diagnostics().await {
                            Ok(diagnostics) => diagnostic_event(
                                diagnostics.irq_status,
                                diagnostics.device_errors,
                                diagnostics.sync_word,
                            ),
                            Err(_) => [EVENT_DIAGNOSTIC, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                        };
                        if !write_all(&mut class, &diagnostic).await {
                            break 'connected;
                        }
                    }
                    usb_command_len = 0;
                    prepare_rx = true;
                    let length_bytes = sent_len.to_le_bytes();
                    let reply = [EVENT_TX, result, length_bytes[0], length_bytes[1]];
                    if !write_all(&mut class, &reply).await {
                        break 'connected;
                    }
                }
            }
        }
    }
}
