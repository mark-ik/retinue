//! Tokio host wrapper for Tulle direct-PHY USB firmware.

use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until};

use crate::PhyProfile;
use crate::airtime::AirtimeBudget;
use crate::direct_phy::{self, Decoder, Event, MAX_FRAME_LEN};
use crate::link::Received;
use crate::lora::LoRaParams;
use crate::serial::{PumpError, PumpStatus, TransmitError};

const INITIALIZATION_RETRY: Duration = Duration::from_millis(500);

/// Runtime settings for a direct-PHY serial link.
#[derive(Clone, Debug)]
pub struct DirectPhySerialConfig {
    pub baud_rate: u32,
    pub open_settle: Duration,
    pub online_timeout: Duration,
    pub transmit_timeout: Duration,
    pub tx_queue: usize,
    pub rx_queue: usize,
}

impl Default for DirectPhySerialConfig {
    fn default() -> Self {
        Self {
            baud_rate: 115_200,
            open_settle: Duration::from_millis(800),
            online_timeout: Duration::from_secs(3),
            transmit_timeout: Duration::from_secs(5),
            tx_queue: 32,
            rx_queue: 32,
        }
    }
}

struct TxRequest {
    frame: Vec<u8>,
    done: oneshot::Sender<Result<Duration, TransmitError>>,
}

struct InFlight {
    request: TxRequest,
    frame_len: usize,
    airtime: Duration,
    deadline: Instant,
}

/// A running serial connection to Tulle direct-PHY firmware.
pub struct DirectPhySerialLink {
    tx: mpsc::Sender<TxRequest>,
    rx: mpsc::Receiver<Received>,
    status: watch::Receiver<PumpStatus>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), io::Error>>>,
}

impl DirectPhySerialLink {
    pub fn open(
        path: impl AsRef<Path>,
        profile: PhyProfile,
        budget: AirtimeBudget,
        config: DirectPhySerialConfig,
    ) -> Result<Self, PumpError> {
        if config.tx_queue == 0 || config.rx_queue == 0 {
            return Err(PumpError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "direct-PHY queue capacities must be non-zero",
            )));
        }
        let port = serial2_tokio::SerialPort::open(path, config.baud_rate)?;
        port.set_dtr(true)?;
        port.set_rts(false)?;
        let params = LoRaParams::try_from(profile).map_err(|message| {
            PumpError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
        })?;
        Ok(Self::spawn_io(port, profile, params, budget, config))
    }

    fn spawn_io<T>(
        io: T,
        profile: PhyProfile,
        params: LoRaParams,
        budget: AirtimeBudget,
        config: DirectPhySerialConfig,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (tx, tx_rx) = mpsc::channel(config.tx_queue);
        let (rx_tx, rx) = mpsc::channel(config.rx_queue);
        let (status_tx, status) = watch::channel(PumpStatus::Settling);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task_status = status_tx.clone();
        let task = tokio::spawn(async move {
            let result = run_pump(
                io,
                profile,
                params,
                budget,
                config,
                tx_rx,
                rx_tx,
                status_tx,
                shutdown_rx,
            )
            .await;
            match &result {
                Ok(()) => {
                    let _ = task_status.send(PumpStatus::Stopped);
                }
                Err(error) => {
                    let _ = task_status.send(PumpStatus::Fault(error.to_string()));
                }
            }
            result
        });

        Self {
            tx,
            rx,
            status,
            shutdown: Some(shutdown),
            task: Some(task),
        }
    }

    pub fn status(&self) -> PumpStatus {
        self.status.borrow().clone()
    }

    pub async fn wait_online(&mut self) -> Result<(), PumpError> {
        loop {
            match self.status.borrow().clone() {
                PumpStatus::Online { .. } => return Ok(()),
                PumpStatus::Fault(message) => return Err(PumpError::Fault(message)),
                PumpStatus::Stopped => return Err(PumpError::Stopped),
                PumpStatus::Settling | PumpStatus::Initializing => {}
            }
            self.status
                .changed()
                .await
                .map_err(|_| PumpError::Stopped)?;
        }
    }

    pub async fn send(&self, frame: impl Into<Vec<u8>>) -> Result<Duration, TransmitError> {
        let (done, result) = oneshot::channel();
        self.tx
            .send(TxRequest {
                frame: frame.into(),
                done,
            })
            .await
            .map_err(|_| TransmitError::Stopped)?;
        result.await.unwrap_or(Err(TransmitError::Stopped))
    }

    pub async fn recv(&mut self) -> Option<Received> {
        self.rx.recv().await
    }

    pub async fn shutdown(mut self) -> Result<(), PumpError> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        match self.task.take() {
            Some(task) => task.await.map_err(PumpError::Task)?.map_err(PumpError::Io),
            None => Ok(()),
        }
    }
}

impl Drop for DirectPhySerialLink {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_pump<T>(
    mut io: T,
    profile: PhyProfile,
    params: LoRaParams,
    mut budget: AirtimeBudget,
    config: DirectPhySerialConfig,
    mut tx_rx: mpsc::Receiver<TxRequest>,
    rx_tx: mpsc::Sender<Received>,
    status_tx: watch::Sender<PumpStatus>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    if !config.open_settle.is_zero() {
        tokio::select! {
            _ = sleep(config.open_settle) => {}
            _ = &mut shutdown => return Ok(()),
        }
    }
    let _ = status_tx.send(PumpStatus::Initializing);
    let configure = direct_phy::encode_configure(profile).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid direct-PHY profile: {error:?}"),
        )
    })?;
    let mut decoder = Decoder::new();
    let mut read_buf = [0_u8; 1024];
    let mut status_bytes = Vec::new();
    let online_deadline = Instant::now() + config.online_timeout;
    let mut next_probe = Instant::now() + INITIALIZATION_RETRY;
    let mut saw_online = false;
    let mut configured = false;
    io.write_all(b"status\n").await?;
    io.flush().await?;
    sleep(Duration::from_millis(20)).await;
    io.write_all(&configure).await?;
    io.flush().await?;
    loop {
        let wake_at = online_deadline.min(next_probe);
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = sleep_until(wake_at) => {
                if Instant::now() >= online_deadline {
                    let missing = match (saw_online, configured) {
                        (false, false) => "online status and radio profile acknowledgement",
                        (false, true) => "online status",
                        (true, false) => "radio profile acknowledgement",
                        (true, true) => unreachable!(),
                    };
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("direct-PHY firmware did not report {missing}"),
                    ));
                }
                io.write_all(b"status\n").await?;
                io.flush().await?;
                sleep(Duration::from_millis(20)).await;
                io.write_all(&configure).await?;
                io.flush().await?;
                next_probe = Instant::now() + INITIALIZATION_RETRY;
            }
            read = io.read(&mut read_buf) => {
                let count = read?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "direct-PHY serial port closed during initialization",
                    ));
                }
                status_bytes.extend_from_slice(&read_buf[..count]);
                if status_bytes.len() > 1024 {
                    status_bytes.drain(..status_bytes.len() - 1024);
                }
                let text = String::from_utf8_lossy(&status_bytes);
                if text.contains("tulle/") && text.contains("phy online") {
                    saw_online = true;
                }
                let mut events = Vec::new();
                decoder.push(&read_buf[..count], &mut events);
                for event in events {
                    match event {
                        Event::Configured { result: 0 } => configured = true,
                        Event::Configured { result } => {
                            return Err(io::Error::other(format!(
                                "direct-PHY firmware rejected the radio profile with result {result}"
                            )));
                        }
                        Event::Received(frame) => {
                            if rx_tx.send(frame).await.is_err() {
                                return Ok(());
                            }
                        }
                        Event::Transmitted { .. } | Event::Diagnostic { .. } => {}
                    }
                }
                if saw_online && configured {
                    break;
                }
            }
        }
    }
    let _ = status_tx.send(PumpStatus::Online { firmware: None });

    let epoch = Instant::now();
    let mut pending: Option<TxRequest> = None;
    let mut in_flight: Option<InFlight> = None;
    let mut retry_at: Option<Instant> = None;
    let mut tx_closed = false;
    let mut last_diagnostic = None;

    loop {
        if pending.is_none() && in_flight.is_none() && !tx_closed {
            match tx_rx.try_recv() {
                Ok(request) => pending = Some(request),
                Err(mpsc::error::TryRecvError::Disconnected) => tx_closed = true,
                Err(mpsc::error::TryRecvError::Empty) => {}
            }
        }

        if let Some(request) = pending.take() {
            if request.frame.len() > MAX_FRAME_LEN {
                let _ = request
                    .done
                    .send(Err(TransmitError::TooLong { max: MAX_FRAME_LEN }));
                retry_at = None;
                continue;
            }
            let now_ms = epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            let airtime_ms = params.time_on_air_ms(request.frame.len());
            if budget.may_transmit(now_ms, airtime_ms) {
                let command = direct_phy::encode_transmit(&request.frame)
                    .expect("frame length checked above");
                io.write_all(&command).await?;
                io.flush().await?;
                budget.record(now_ms, airtime_ms);
                let airtime = params.time_on_air(request.frame.len());
                in_flight = Some(InFlight {
                    frame_len: request.frame.len(),
                    request,
                    airtime,
                    deadline: Instant::now() + config.transmit_timeout,
                });
                retry_at = None;
            } else if let Some(next_ms) = budget.next_slot(now_ms, airtime_ms) {
                pending = Some(request);
                retry_at = Some(epoch + Duration::from_millis(next_ms));
            } else {
                let _ = request.done.send(Err(TransmitError::DutyCycleImpossible));
                retry_at = None;
            }
        }

        if tx_closed && pending.is_none() && in_flight.is_none() {
            return Ok(());
        }

        let wake_at = match (&in_flight, retry_at) {
            (Some(sent), Some(retry)) => sent.deadline.min(retry),
            (Some(sent), None) => sent.deadline,
            (None, Some(retry)) => retry,
            (None, None) => Instant::now() + Duration::from_secs(3600),
        };

        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            request = tx_rx.recv(), if pending.is_none() && in_flight.is_none() && !tx_closed => {
                match request {
                    Some(request) => pending = Some(request),
                    None => tx_closed = true,
                }
            }
            read = io.read(&mut read_buf) => {
                let count = read?;
                if count == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "direct-PHY serial port closed"));
                }
                let mut events = Vec::new();
                decoder.push(&read_buf[..count], &mut events);
                for event in events {
                    match event {
                        Event::Received(frame) => {
                            if rx_tx.send(frame).await.is_err() {
                                return Ok(());
                            }
                        }
                        Event::Transmitted { result, frame_len } => {
                            if let Some(sent) = in_flight.take() {
                                let outcome = if result == 0 && frame_len == sent.frame_len {
                                    Ok(sent.airtime)
                                } else {
                                    let diagnostic = last_diagnostic
                                        .take()
                                        .map(|(irq, errors, sync): (u16, u16, [u8; 2])| {
                                            format!(
                                                "; irq=0x{irq:04x} errors=0x{errors:04x} sync={:02x}{:02x}",
                                                sync[0], sync[1]
                                            )
                                        })
                                        .unwrap_or_default();
                                    Err(TransmitError::Transport(format!(
                                        "direct-PHY transmit result {result}, length {frame_len}, expected {}{diagnostic}",
                                        sent.frame_len,
                                    )))
                                };
                                let _ = sent.request.done.send(outcome);
                            }
                        }
                        Event::Configured { .. } => {}
                        Event::Diagnostic {
                            irq_status,
                            device_errors,
                            sync_word,
                        } => {
                            last_diagnostic = Some((irq_status, device_errors, sync_word));
                        }
                    }
                }
            }
            _ = sleep_until(wake_at) => {
                if in_flight.as_ref().is_some_and(|sent| sent.deadline <= Instant::now()) {
                    if let Some(sent) = in_flight.take() {
                        let _ = sent.request.done.send(Err(TransmitError::Transport(
                            "direct-PHY transmit acknowledgement timed out".to_string(),
                        )));
                    }
                }
                if retry_at.is_some_and(|retry| retry <= Instant::now()) {
                    retry_at = None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lora::CodingRate;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn params() -> LoRaParams {
        LoRaParams {
            spreading_factor: 11,
            bandwidth_hz: 250_000,
            coding_rate: CodingRate::Cr45,
            frequency_hz: 906_875_000,
            tx_power_dbm: 17,
            preamble_syms: 16,
            explicit_header: true,
            crc: true,
        }
    }

    fn profile() -> PhyProfile {
        PhyProfile::meshtastic_long_fast(906_875_000)
    }

    #[tokio::test]
    async fn pump_sends_and_receives_complete_frames() {
        let (host, mut firmware) = tokio::io::duplex(2048);
        let config = DirectPhySerialConfig {
            open_settle: Duration::ZERO,
            transmit_timeout: Duration::from_secs(1),
            ..Default::default()
        };
        let budget = AirtimeBudget::new(60_000, 1000);
        let mut link = DirectPhySerialLink::spawn_io(host, profile(), params(), budget, config);

        let firmware_task = tokio::spawn(async move {
            let mut status = [0_u8; 7];
            firmware.read_exact(&mut status).await.unwrap();
            assert_eq!(&status, b"status\n");
            firmware
                .write_all(b"tulle/test phy online\r\n")
                .await
                .unwrap();

            let mut configure = [0_u8; tulle_phy_profile::CONFIG_COMMAND_LEN];
            firmware.read_exact(&mut configure).await.unwrap();
            assert_eq!(
                tulle_phy_profile::decode_config_command(&configure),
                Ok(profile())
            );
            firmware
                .write_all(&[direct_phy::EVENT_CONFIG, 0])
                .await
                .unwrap();

            let mut command = [0_u8; 8];
            firmware.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"\x01\x05\x00hello");
            firmware
                .write_all(&[direct_phy::EVENT_RX, 3, 0, 0xd8, 0xff, 9, 0, 7, 8, 9])
                .await
                .unwrap();
            firmware
                .write_all(&[direct_phy::EVENT_TX, 0, 5, 0])
                .await
                .unwrap();
            sleep(Duration::from_secs(1)).await;
        });

        link.wait_online().await.unwrap();
        let airtime = link.send(b"hello".to_vec()).await.unwrap();
        assert_eq!(airtime, params().time_on_air(5));
        let received = link.recv().await.unwrap();
        assert_eq!(received.frame, [7, 8, 9]);
        assert_eq!(received.rssi_dbm, -40);
        assert_eq!(received.snr_db, 9.0);
        link.shutdown().await.unwrap();
        firmware_task.await.unwrap();
    }

    #[tokio::test]
    async fn pump_retries_status_and_profile_during_startup() {
        let (host, mut firmware) = tokio::io::duplex(2048);
        let config = DirectPhySerialConfig {
            open_settle: Duration::ZERO,
            online_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let budget = AirtimeBudget::new(60_000, 1000);
        let mut link = DirectPhySerialLink::spawn_io(host, profile(), params(), budget, config);

        let firmware_task = tokio::spawn(async move {
            let mut status = [0_u8; 7];
            firmware.read_exact(&mut status).await.unwrap();
            assert_eq!(&status, b"status\n");
            let mut configure = [0_u8; tulle_phy_profile::CONFIG_COMMAND_LEN];
            firmware.read_exact(&mut configure).await.unwrap();
            assert_eq!(
                tulle_phy_profile::decode_config_command(&configure),
                Ok(profile())
            );

            firmware.read_exact(&mut status).await.unwrap();
            assert_eq!(&status, b"status\n");
            firmware
                .write_all(b"tulle/test phy online\r\n")
                .await
                .unwrap();
            firmware.read_exact(&mut configure).await.unwrap();
            assert_eq!(
                tulle_phy_profile::decode_config_command(&configure),
                Ok(profile())
            );
            firmware
                .write_all(&[direct_phy::EVENT_CONFIG, 0])
                .await
                .unwrap();
            sleep(Duration::from_secs(1)).await;
        });

        link.wait_online().await.unwrap();
        link.shutdown().await.unwrap();
        firmware_task.await.unwrap();
    }
}
