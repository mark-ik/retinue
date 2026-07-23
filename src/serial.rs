//! Tokio serial transport for an RNode-backed [`RadioLink`](crate::link::RadioLink).
//!
//! This is the real-I/O edge around Tulle's sans-I/O radio state machine. It owns the
//! serial port, initialization retries, transmit pacing, and the clock used by the shared
//! airtime budget. Protocol crates see complete frames through [`RNodeSerialLink`]; they do
//! not depend on RNode's KISS framing or serial details.

use std::fmt;
use std::io;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, sleep_until};

use crate::airtime::AirtimeBudget;
use crate::link::{RadioLink, Received, SendOutcome};
use crate::lora::LoRaParams;
use crate::modem::ModemError;
use crate::rnode::RNode;

/// Runtime policy for the serial pump. Durations are settings because USB devices and
/// half-duplex radios need different settle and turnaround margins.
#[derive(Clone, Debug)]
pub struct SerialPumpConfig {
    /// Serial line rate used by RNode firmware.
    pub baud_rate: u32,
    /// Time allowed for a board reset triggered by opening its USB serial port.
    pub open_settle: Duration,
    /// How often to repeat the RNode detect/configuration conversation until it is online.
    pub init_retry: Duration,
    /// Receive window left after each packet's calculated airtime.
    pub turnaround: Duration,
    /// Retry delay when the modem reports its half-duplex queue busy.
    pub busy_retry: Duration,
    /// Maximum number of frames waiting for the radio.
    pub tx_queue: usize,
    /// Maximum number of received frames waiting for the protocol consumer.
    pub rx_queue: usize,
}

impl Default for SerialPumpConfig {
    fn default() -> Self {
        Self {
            baud_rate: 115_200,
            open_settle: Duration::from_secs(3),
            init_retry: Duration::from_secs(6),
            turnaround: Duration::from_millis(180),
            busy_retry: Duration::from_millis(50),
            tx_queue: 32,
            rx_queue: 32,
        }
    }
}

/// Observable lifecycle of the pump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpStatus {
    Settling,
    Initializing,
    Online { firmware: Option<(u8, u8)> },
    Fault(String),
    Stopped,
}

/// A frame rejected after it reached the radio pump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransmitError {
    TooLong { max: usize },
    Unsupported,
    DutyCycleImpossible,
    Transport(String),
    Stopped,
}

impl fmt::Display for TransmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max } => write!(f, "frame exceeds max length {max}"),
            Self::Unsupported => write!(f, "radio parameters are unsupported"),
            Self::DutyCycleImpossible => {
                write!(f, "frame cannot fit the configured airtime budget")
            }
            Self::Transport(message) => write!(f, "serial transport error: {message}"),
            Self::Stopped => write!(f, "serial pump stopped"),
        }
    }
}

impl std::error::Error for TransmitError {}

/// Error opening, awaiting, or shutting down a pump.
#[derive(Debug)]
pub enum PumpError {
    Io(io::Error),
    Fault(String),
    Stopped,
    Task(tokio::task::JoinError),
}

impl fmt::Display for PumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "serial I/O failed: {error}"),
            Self::Fault(message) => write!(f, "serial pump failed: {message}"),
            Self::Stopped => write!(f, "serial pump stopped"),
            Self::Task(error) => write!(f, "serial pump task failed: {error}"),
        }
    }
}

impl std::error::Error for PumpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Task(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for PumpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct TxRequest {
    frame: Vec<u8>,
    done: oneshot::Sender<Result<Duration, TransmitError>>,
}

/// A running RNode serial interface.
///
/// Opening asserts DTR, explicitly deasserts RTS, and starts one Tokio task that owns all
/// serial reads and writes. [`send`](Self::send) completes after the frame passes the airtime
/// gate and its KISS bytes have been written. [`recv`](Self::recv) yields complete RF frames.
pub struct RNodeSerialLink {
    tx: mpsc::Sender<TxRequest>,
    rx: mpsc::Receiver<Received>,
    status: watch::Receiver<PumpStatus>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<Result<(), io::Error>>>,
}

impl RNodeSerialLink {
    /// Open a real serial port and start the pump.
    pub fn open(
        path: impl AsRef<Path>,
        params: LoRaParams,
        budget: AirtimeBudget,
        config: SerialPumpConfig,
    ) -> Result<Self, PumpError> {
        if config.tx_queue == 0 || config.rx_queue == 0 {
            return Err(PumpError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "serial pump queue capacities must be non-zero",
            )));
        }

        let port = serial2_tokio::SerialPort::open(path, config.baud_rate)?;
        // nRF USB CDC gates output on DTR. On ESP32, RTS is wired into reset/boot and must
        // remain deasserted; an earlier live harness wedged the board by asserting it.
        port.set_dtr(true)?;
        port.set_rts(false)?;
        Ok(Self::spawn_io(port, params, budget, config))
    }

    fn spawn_io<T>(
        io: T,
        params: LoRaParams,
        budget: AirtimeBudget,
        config: SerialPumpConfig,
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
                RadioLink::new(RNode::new(params), budget),
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

    /// Current lifecycle state without waiting.
    pub fn status(&self) -> PumpStatus {
        self.status.borrow().clone()
    }

    /// Wait until the RNode confirms that its radio is online.
    pub async fn wait_online(&mut self) -> Result<Option<(u8, u8)>, PumpError> {
        loop {
            match self.status.borrow().clone() {
                PumpStatus::Online { firmware } => return Ok(firmware),
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

    /// Queue one complete RF frame and wait until it has passed the shared airtime gate and
    /// its serial bytes have been written to the RNode.
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

    /// Receive the next complete RF frame and its link metrics.
    pub async fn recv(&mut self) -> Option<Received> {
        self.rx.recv().await
    }

    /// Stop the task and wait for the serial port to close.
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

impl Drop for RNodeSerialLink {
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
    mut link: RadioLink<RNode>,
    config: SerialPumpConfig,
    mut tx_rx: mpsc::Receiver<TxRequest>,
    rx_tx: mpsc::Sender<Received>,
    status_tx: watch::Sender<PumpStatus>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), io::Error>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let epoch = Instant::now();
    if !config.open_settle.is_zero() {
        tokio::select! {
            _ = sleep(config.open_settle) => {}
            _ = &mut shutdown => return Ok(()),
        }
    }

    let _ = status_tx.send(PumpStatus::Initializing);
    link.modem_mut().start();
    flush_modem(&mut io, &mut link).await?;
    let mut next_init = Instant::now() + config.init_retry;
    let mut next_tx = Instant::now();
    let mut pending: Option<TxRequest> = None;
    let mut tx_closed = false;
    let mut announced_online = false;
    let mut read_buf = [0u8; 1024];

    loop {
        while let Some(received) = link.recv() {
            if rx_tx.send(received).await.is_err() {
                return Ok(());
            }
        }

        if link.modem().is_online() && !announced_online {
            announced_online = true;
            let _ = status_tx.send(PumpStatus::Online {
                firmware: link.modem().fw_version(),
            });
        }

        let now = Instant::now();
        if !link.modem().is_online() && now >= next_init {
            link.modem_mut().start();
            flush_modem(&mut io, &mut link).await?;
            next_init = Instant::now() + config.init_retry;
        }

        if pending.is_some() && link.modem().is_online() && now >= next_tx {
            let request = pending.take().expect("checked above");
            let now_ms = epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            match link.send(&request.frame, now_ms) {
                SendOutcome::Sent { airtime } => {
                    if let Err(error) = flush_modem(&mut io, &mut link).await {
                        let _ = request
                            .done
                            .send(Err(TransmitError::Transport(error.to_string())));
                        return Err(error);
                    }
                    next_tx = Instant::now() + airtime + config.turnaround;
                    let _ = request.done.send(Ok(airtime));
                }
                SendOutcome::DutyCycleBlocked {
                    retry_at_ms: Some(retry_at_ms),
                } => {
                    next_tx = epoch + Duration::from_millis(retry_at_ms);
                    pending = Some(request);
                }
                SendOutcome::DutyCycleBlocked { retry_at_ms: None } => {
                    let _ = request.done.send(Err(TransmitError::DutyCycleImpossible));
                }
                SendOutcome::Failed(ModemError::Busy) => {
                    next_tx = Instant::now() + config.busy_retry;
                    pending = Some(request);
                }
                SendOutcome::Failed(ModemError::TooLong { max }) => {
                    let _ = request.done.send(Err(TransmitError::TooLong { max }));
                }
                SendOutcome::Failed(ModemError::Unsupported) => {
                    let _ = request.done.send(Err(TransmitError::Unsupported));
                }
                SendOutcome::Failed(ModemError::Transport(error)) => {
                    let _ = request
                        .done
                        .send(Err(TransmitError::Transport(error.to_string())));
                }
            }
            continue;
        }

        let wake = if !link.modem().is_online() {
            next_init
        } else if pending.is_some() {
            next_tx
        } else {
            // A bounded wake keeps status/event draining prompt even on serial drivers that
            // do not produce a readiness edge for modem-control changes.
            Instant::now() + Duration::from_millis(250)
        };

        tokio::select! {
            biased;
            _ = &mut shutdown => return Ok(()),
            read = io.read(&mut read_buf) => {
                let count = read?;
                if count == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "serial port closed"));
                }
                link.modem_mut().on_serial(&read_buf[..count]);
                flush_modem(&mut io, &mut link).await?;
            }
            request = tx_rx.recv(), if pending.is_none() && !tx_closed => {
                match request {
                    Some(request) => pending = Some(request),
                    None => tx_closed = true,
                }
            }
            _ = sleep_until(wake) => {}
        }
    }
}

async fn flush_modem<T>(io: &mut T, link: &mut RadioLink<RNode>) -> Result<(), io::Error>
where
    T: AsyncWrite + Unpin,
{
    let bytes = link.modem_mut().take_outbound();
    if !bytes.is_empty() {
        io.write_all(&bytes).await?;
        io.flush().await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kiss;
    use crate::lora::CodingRate;
    use crate::rnode::cmd;
    use tokio::io::DuplexStream;

    fn params() -> LoRaParams {
        LoRaParams {
            spreading_factor: 7,
            bandwidth_hz: 125_000,
            coding_rate: CodingRate::Cr45,
            frequency_hz: 915_000_000,
            tx_power_dbm: 7,
            preamble_syms: 8,
            explicit_header: true,
            crc: true,
        }
    }

    fn config() -> SerialPumpConfig {
        SerialPumpConfig {
            open_settle: Duration::ZERO,
            init_retry: Duration::from_millis(100),
            turnaround: Duration::from_millis(20),
            busy_retry: Duration::from_millis(5),
            ..SerialPumpConfig::default()
        }
    }

    async fn emulate_rnode(mut device: DuplexStream) -> Vec<Instant> {
        let mut deframer = kiss::Deframer::new(600);
        let mut read = [0u8; 256];
        let mut data_times = Vec::new();
        loop {
            let count = device.read(&mut read).await.expect("host read");
            if count == 0 {
                break;
            }
            let mut frames = Vec::new();
            deframer.push(&read[..count], &mut frames);
            for frame in frames {
                let (&command, payload) = frame.split_first().expect("command");
                let response = match command {
                    cmd::DETECT => Some(vec![cmd::DETECT, crate::rnode::DETECT_RESP]),
                    cmd::FW_VERSION => Some(vec![cmd::FW_VERSION, 1, 86]),
                    cmd::RADIO_STATE => Some(vec![cmd::RADIO_STATE, 1]),
                    cmd::DATA => {
                        data_times.push(Instant::now());
                        let mut response = vec![cmd::STAT_RSSI, 117]; // -40 dBm
                        device.write_all(&kiss::encode(&response)).await.unwrap();
                        response = vec![cmd::STAT_SNR, 32]; // 8 dB
                        device.write_all(&kiss::encode(&response)).await.unwrap();
                        response = vec![cmd::DATA];
                        response.extend_from_slice(payload);
                        Some(response)
                    }
                    _ => None,
                };
                if let Some(response) = response {
                    device.write_all(&kiss::encode(&response)).await.unwrap();
                }
            }
        }
        data_times
    }

    #[tokio::test]
    async fn initializes_paces_and_delivers_frames() {
        let (host, device) = tokio::io::duplex(4096);
        let emulator = tokio::spawn(emulate_rnode(device));
        let mut pump =
            RNodeSerialLink::spawn_io(host, params(), AirtimeBudget::new(60_000, 1000), config());

        assert_eq!(pump.wait_online().await.unwrap(), Some((1, 86)));
        let first_airtime = pump.send(b"one".to_vec()).await.unwrap();
        let second_airtime = pump.send(b"two".to_vec()).await.unwrap();
        assert_eq!(first_airtime, second_airtime);

        let first = pump.recv().await.expect("first echo");
        let second = pump.recv().await.expect("second echo");
        assert_eq!(first.frame, b"one");
        assert_eq!(second.frame, b"two");
        assert_eq!((first.rssi_dbm, first.snr_db), (-40, 8.0));

        pump.shutdown().await.unwrap();
        let times = emulator.await.unwrap();
        assert_eq!(times.len(), 2);
        assert!(
            times[1].duration_since(times[0]) >= first_airtime + config().turnaround,
            "second frame was not paced by airtime plus turnaround"
        );
    }

    #[tokio::test]
    async fn rejects_a_frame_that_can_never_fit_the_budget() {
        let (host, device) = tokio::io::duplex(4096);
        let emulator = tokio::spawn(emulate_rnode(device));
        let mut pump =
            RNodeSerialLink::spawn_io(host, params(), AirtimeBudget::new(1_000, 1), config());
        pump.wait_online().await.unwrap();
        assert_eq!(
            pump.send(b"cannot fit".to_vec()).await.unwrap_err(),
            TransmitError::DutyCycleImpossible
        );
        pump.shutdown().await.unwrap();
        assert!(emulator.await.unwrap().is_empty());
    }
}
