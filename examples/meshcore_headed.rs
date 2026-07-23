//! Headed compatibility acceptance against an unmodified MeshCore companion.
//!
//! COM6 runs Tulle direct-PHY firmware. COM8 runs the official MeshCore
//! companion USB firmware. The companion API is used only for node management;
//! adverts, encrypted text, path replies, and acknowledgements cross the radio.

use std::collections::VecDeque;
use std::io;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serial2_tokio::SerialPort;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, timeout, timeout_at};
use tucket::advert::AdvertData;
use tucket::identity::LocalIdentity;
use tucket::node::{DirectRoute, Event, Node};
use tucket::packet::Packet;
use tulle::PhyProfile;
use tulle::airtime::AirtimeBudget;
use tulle::direct_phy_serial::{DirectPhySerialConfig, DirectPhySerialLink};

const CMD_APP_START: u8 = 1;
const CMD_SEND_TXT_MSG: u8 = 2;
const CMD_SET_DEVICE_TIME: u8 = 6;
const CMD_SEND_SELF_ADVERT: u8 = 7;
const CMD_SET_ADVERT_NAME: u8 = 8;
const CMD_ADD_UPDATE_CONTACT: u8 = 9;
const CMD_IMPORT_CONTACT: u8 = 18;
const CMD_GET_CONTACT_BY_KEY: u8 = 30;
const CMD_SYNC_NEXT_MESSAGE: u8 = 10;
const CMD_SET_RADIO_PARAMS: u8 = 11;
const CMD_RESET_PATH: u8 = 13;
const CMD_DEVICE_QUERY: u8 = 22;

const RESP_OK: u8 = 0;
const RESP_ERR: u8 = 1;
const RESP_SELF_INFO: u8 = 5;
const RESP_SENT: u8 = 6;
const RESP_CONTACT_MESSAGE_V3: u8 = 16;
const RESP_DEVICE_INFO: u8 = 13;
const RESP_CONTACT: u8 = 3;
const PUSH_SEND_CONFIRMED: u8 = 0x82;

struct Companion {
    port: SerialPort,
    pushes: VecDeque<Vec<u8>>,
}

impl Companion {
    fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let port = SerialPort::open(path, 115_200)?;
        // The companion's native USB CDC endpoint begins delivering frames
        // after the host asserts DTR. This does not enter the ESP32 flasher;
        // that is the separate PID 0x1001 endpoint.
        port.set_dtr(true)?;
        port.set_rts(false)?;
        Ok(Self {
            port,
            pushes: VecDeque::new(),
        })
    }

    async fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "companion frame too long"))?;
        self.port.write_all(b"<").await?;
        self.port.write_all(&len.to_le_bytes()).await?;
        self.port.write_all(payload).await?;
        self.port.flush().await
    }

    async fn read_frame(&mut self, wait: Duration) -> io::Result<Vec<u8>> {
        timeout(wait, async {
            loop {
                if self.port.read_u8().await? == b'>' {
                    break;
                }
            }
            let len = self.port.read_u16_le().await? as usize;
            let mut frame = vec![0; len];
            self.port.read_exact(&mut frame).await?;
            Ok(frame)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MeshCore response timed out"))?
    }

    async fn command(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        self.send_frame(payload).await?;
        loop {
            let frame = self.read_frame(Duration::from_secs(15)).await?;
            let Some(&code) = frame.first() else {
                continue;
            };
            if code >= 0x80 {
                self.pushes.push_back(frame);
                continue;
            }
            if code == RESP_ERR {
                return Err(io::Error::other(format!(
                    "MeshCore command {} failed with error {}",
                    payload[0],
                    frame.get(1).copied().unwrap_or(0)
                )));
            }
            return Ok(frame);
        }
    }

    async fn expect(&mut self, payload: &[u8], expected: u8) -> io::Result<Vec<u8>> {
        let frame = self.command(payload).await?;
        if frame.first() != Some(&expected) {
            return Err(io::Error::other(format!(
                "MeshCore command {} returned {:?}, expected {expected}",
                payload[0],
                frame.first()
            )));
        }
        Ok(frame)
    }

    async fn wait_push(&mut self, expected: u8, wait: Duration) -> io::Result<Vec<u8>> {
        if let Some(index) = self
            .pushes
            .iter()
            .position(|frame| frame.first() == Some(&expected))
        {
            return Ok(self.pushes.remove(index).expect("index just found"));
        }
        let deadline = Instant::now() + wait;
        loop {
            let frame = timeout_at(deadline, self.read_frame(wait))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "MeshCore push timed out")
                })??;
            if frame.first() == Some(&expected) {
                return Ok(frame);
            }
            if frame.first().is_some_and(|code| *code >= 0x80) {
                self.pushes.push_back(frame);
            }
        }
    }

    async fn set_contact_route(&mut self, public_key: &[u8; 32], path: &[u8]) -> io::Result<()> {
        if path.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MeshCore V1 route exceeds 63 hops",
            ));
        }
        let mut get = vec![CMD_GET_CONTACT_BY_KEY];
        get.extend_from_slice(public_key);
        let mut contact = self.expect(&get, RESP_CONTACT).await?;
        const PATH_LEN_AT: usize = 35;
        const PATH_AT: usize = 36;
        const PATH_CAPACITY: usize = 64;
        if contact.len() < PATH_AT + PATH_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated MeshCore contact",
            ));
        }
        contact[0] = CMD_ADD_UPDATE_CONTACT;
        contact[PATH_LEN_AT] = path.len() as u8;
        contact[PATH_AT..PATH_AT + PATH_CAPACITY].fill(0);
        contact[PATH_AT..PATH_AT + path.len()].copy_from_slice(path);
        self.expect(&contact, RESP_OK).await?;
        Ok(())
    }
}

fn now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs() as u32
}

fn radio_params(frequency_hz: u32) -> PhyProfile {
    PhyProfile::meshcore(frequency_hz, 250_000, 10, 5)
}

fn radio_command(frequency_hz: u32) -> Vec<u8> {
    let mut command = vec![CMD_SET_RADIO_PARAMS];
    command.extend_from_slice(&(frequency_hz / 1_000).to_le_bytes());
    command.extend_from_slice(&250_000_u32.to_le_bytes());
    command.extend_from_slice(&[10, 5, 0]);
    command
}

fn import_command(advert: &[u8]) -> Vec<u8> {
    let mut command = Vec::with_capacity(1 + advert.len());
    command.push(CMD_IMPORT_CONTACT);
    command.extend_from_slice(advert);
    command
}

fn text_command(peer_prefix: &[u8; 6], timestamp: u32, text: &str) -> Vec<u8> {
    let mut command = vec![CMD_SEND_TXT_MSG, 0, 0];
    command.extend_from_slice(&timestamp.to_le_bytes());
    command.extend_from_slice(peer_prefix);
    command.extend_from_slice(text.as_bytes());
    command
}

fn contact_text(frame: &[u8]) -> Option<&str> {
    if frame.first() != Some(&RESP_CONTACT_MESSAGE_V3) || frame.len() < 16 {
        return None;
    }
    std::str::from_utf8(&frame[16..]).ok()
}

fn relay_hash(value: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(
        value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value),
        16,
    )
}

async fn sync_text(companion: &mut Companion, wait: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + wait;
    loop {
        let frame = companion.command(&[CMD_SYNC_NEXT_MESSAGE]).await?;
        if frame.first() == Some(&RESP_CONTACT_MESSAGE_V3) {
            return Ok(frame);
        }
        if frame.first() != Some(&10) {
            return Err(io::Error::other(format!(
                "unexpected MeshCore message-sync response {:?}",
                frame.first()
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "MeshCore text did not reach its offline queue",
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn receive_ack_and_route(
    link: &mut DirectPhySerialLink,
    node: &mut Node,
    peer_hash: u8,
    expected_ack: [u8; 4],
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut acknowledged = false;
    loop {
        let received = timeout_at(deadline, link.recv())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MeshCore ACK timed out"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "radio stopped"))?;
        let (events, outgoing) = node.on_frame(&received.frame);
        for event in events {
            if matches!(event, Event::Ack(ack) if ack == expected_ack) {
                acknowledged = true;
            }
        }
        for frame in outgoing {
            link.send(frame)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        if acknowledged && node.route_to(peer_hash).is_some() {
            return Ok(());
        }
    }
}

async fn receive_text(
    link: &mut DirectPhySerialLink,
    node: &mut Node,
    expected: &str,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let received = timeout_at(deadline, link.recv())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MeshCore text timed out"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "radio stopped"))?;
        let (events, outgoing) = node.on_frame(&received.frame);
        for frame in outgoing {
            link.send(frame)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        for event in events {
            if let Event::Message { from, message, ack } = event {
                let ack = node.ack_frame_to(from, ack);
                link.send(ack)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
                if message.text == expected {
                    return Ok(());
                }
            }
        }
    }
}

async fn receive_route(
    link: &mut DirectPhySerialLink,
    node: &mut Node,
    peer_hash: u8,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while node.route_to(peer_hash).is_none() {
        let received = timeout_at(deadline, link.recv())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "MeshCore path timed out"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "radio stopped"))?;
        let (_, outgoing) = node.on_frame(&received.frame);
        for frame in outgoing {
            link.send(frame)
                .await
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let tulle_port = args.next().unwrap_or_else(|| "COM6".into());
    let meshcore_port = args.next().unwrap_or_else(|| "COM8".into());
    let frequency_hz = args
        .next()
        .map(|value| value.parse::<u32>())
        .transpose()?
        .unwrap_or(915_000_000);
    let relay_hash = args.next().map(|value| relay_hash(&value)).transpose()?;

    let mut companion = Companion::open(&meshcore_port)?;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let device = companion
        .expect(&[CMD_DEVICE_QUERY, 10], RESP_DEVICE_INFO)
        .await?;
    let firmware_protocol = device.get(1).copied().unwrap_or(0);
    let mut app_start = vec![CMD_APP_START, 0, 0, 0, 0, 0, 0, 0];
    app_start.extend_from_slice(b"tucket-headed");
    let self_info = companion.expect(&app_start, RESP_SELF_INFO).await?;
    let stock_public: [u8; 32] = self_info
        .get(4..36)
        .ok_or("truncated MeshCore self info")?
        .try_into()?;
    companion
        .expect(&radio_command(frequency_hz), RESP_OK)
        .await?;
    companion
        .expect(
            &[
                CMD_SET_ADVERT_NAME,
                b'M',
                b'e',
                b's',
                b'h',
                b'C',
                b'o',
                b'r',
                b'e',
            ],
            RESP_OK,
        )
        .await?;
    let mut set_time = vec![CMD_SET_DEVICE_TIME];
    set_time.extend_from_slice(&now().to_le_bytes());
    companion.expect(&set_time, RESP_OK).await?;

    let mut link = DirectPhySerialLink::open(
        &tulle_port,
        radio_params(frequency_hz),
        AirtimeBudget::new(60_000, 60_000),
        DirectPhySerialConfig::default(),
    )?;
    timeout(Duration::from_secs(10), link.wait_online()).await??;
    println!(
        "radios online: {tulle_port}=Tulle direct PHY, {meshcore_port}=MeshCore companion protocol {firmware_protocol}"
    );

    let identity = LocalIdentity::from_seed([0x54; 32]);
    let tucket_public = identity.identity().pub_key;
    let mut tucket_prefix = [0_u8; 6];
    tucket_prefix.copy_from_slice(&tucket_public[..6]);
    let mut node = Node::new(identity, false);

    let advert_data = AdvertData::chat("Tucket");
    let imported_advert = node
        .advert_frame_data(now(), &advert_data)
        .ok_or("Tucket advert data is too long")?;
    companion
        .expect(&import_command(&imported_advert), RESP_OK)
        .await?;
    link.send(
        node.advert_frame_data(now().wrapping_add(1), &advert_data)
            .ok_or("Tucket advert data is too long")?,
    )
    .await?;
    companion
        .expect(&[CMD_SEND_SELF_ADVERT, 1], RESP_OK)
        .await?;

    let stock_hash = stock_public[0];
    let advert_deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let received = timeout_at(advert_deadline, link.recv())
            .await?
            .ok_or("radio stopped while awaiting MeshCore advert")?;
        let (events, outgoing) = node.on_frame(&received.frame);
        for frame in outgoing {
            link.send(frame).await?;
        }
        if events.iter().any(
            |event| matches!(event, Event::Advert { identity, .. } if identity.pub_key == stock_public),
        ) {
            break;
        }
    }
    println!("authenticated adverts crossed the MeshCore/Tucket boundary");

    if let Some(relay_hash) = relay_hash {
        let route = DirectRoute::new(1, &[relay_hash]).ok_or("invalid one-hop relay route")?;
        if !node.set_route(stock_hash, route) {
            return Err("MeshCore contact disappeared before route installation".into());
        }
        companion
            .set_contact_route(&tucket_public, &[relay_hash])
            .await?;
        println!("forced reciprocal one-hop route through relay {relay_hash:02x}");

        let tucket_text = "Tucket source route crossed the relay";
        let (frame, expected_ack) = node
            .text_frame(stock_hash, now().wrapping_add(1), tucket_text)
            .ok_or("MeshCore contact disappeared")?;
        let packet = Packet::decode(&frame).ok_or("Tucket emitted a malformed packet")?;
        if packet.is_flood() || packet.path != [relay_hash] {
            return Err("Tucket did not select the forced relay route".into());
        }
        link.send(frame).await?;
        let received = sync_text(&mut companion, Duration::from_secs(45)).await?;
        if contact_text(&received) != Some(tucket_text) {
            return Err(format!(
                "MeshCore decoded unexpected relayed text: {:?}",
                contact_text(&received)
            )
            .into());
        }
        receive_ack_and_route(&mut link, &mut node, stock_hash, expected_ack).await?;
        if node
            .route_to(stock_hash)
            .is_none_or(|route| route.path() != [relay_hash])
        {
            return Err("Tucket relay route changed while receiving the ACK".into());
        }
        println!("Tucket text and MeshCore ACK crossed the relay");

        let stock_text = "MeshCore source route crossed the relay";
        let sent = companion
            .expect(
                &text_command(&tucket_prefix, now().wrapping_add(2), stock_text),
                RESP_SENT,
            )
            .await?;
        if sent.get(1) != Some(&0) {
            return Err(
                "stock MeshCore flooded instead of selecting the forced relay route".into(),
            );
        }
        receive_text(&mut link, &mut node, stock_text).await?;
        companion
            .wait_push(PUSH_SEND_CONFIRMED, Duration::from_secs(45))
            .await?;
        println!("MeshCore text and Tucket ACK crossed the relay");
        println!("TUCKET MESHCORE RELAY HEADED PASSED");
        link.shutdown().await?;
        return Ok(());
    }

    let mut reset_path = vec![CMD_RESET_PATH];
    reset_path.extend_from_slice(&tucket_public);
    companion.expect(&reset_path, RESP_OK).await?;

    let first_text = "Stock MeshCore flood establishes a route";
    let sent = companion
        .expect(&text_command(&tucket_prefix, now(), first_text), RESP_SENT)
        .await?;
    if sent.get(1) != Some(&1) {
        return Err("stock MeshCore did not flood the route-discovery text".into());
    }
    receive_text(&mut link, &mut node, first_text).await?;
    companion
        .wait_push(PUSH_SEND_CONFIRMED, Duration::from_secs(45))
        .await?;
    receive_route(&mut link, &mut node, stock_hash).await?;
    println!("stock flood text, encrypted ACK, and reciprocal route passed");

    let direct_text = "Tucket direct route works";
    let (direct_frame, direct_ack) = node
        .text_frame(stock_hash, now().wrapping_add(1), direct_text)
        .ok_or("MeshCore contact disappeared")?;
    if Packet::decode(&direct_frame).is_none_or(|packet| packet.is_flood()) {
        return Err("second Tucket text did not select the learned direct route".into());
    }
    link.send(direct_frame).await?;
    let direct_received = sync_text(&mut companion, Duration::from_secs(45)).await?;
    if contact_text(&direct_received) != Some(direct_text) {
        return Err(format!(
            "MeshCore decoded unexpected direct text: {:?}",
            contact_text(&direct_received)
        )
        .into());
    }
    receive_ack_and_route(&mut link, &mut node, stock_hash, direct_ack).await?;
    println!("Tucket selected its learned direct route");

    let stock_text = "Stock MeshCore second direct reply";
    let sent = companion
        .expect(
            &text_command(&tucket_prefix, now().wrapping_add(2), stock_text),
            RESP_SENT,
        )
        .await?;
    if sent.get(1) != Some(&0) {
        return Err("stock MeshCore flooded instead of selecting its learned route".into());
    }
    receive_text(&mut link, &mut node, stock_text).await?;
    companion
        .wait_push(PUSH_SEND_CONFIRMED, Duration::from_secs(45))
        .await?;
    println!("stock MeshCore selected the reciprocal route and received Tucket's ACK");
    println!("TUCKET MESHCORE HEADED PASSED");

    link.shutdown().await?;
    Ok(())
}
