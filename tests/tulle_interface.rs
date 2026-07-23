use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use retinue::destination::DestinationName;
use retinue::endpoint::Endpoint;
use retinue::identity::PrivateIdentity;
use retinue::iface::tulle::drive;
use tokio::sync::{Notify, mpsc};
use tulle::link::Received;
use tulle::radio_io::PacketRadio;
use tulle::serial::TransmitError;

struct MemoryRadio {
    peer: mpsc::UnboundedSender<Vec<u8>>,
    inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    sent: Arc<Mutex<VecDeque<Vec<u8>>>>,
    notify: Arc<Notify>,
    max_frame_len: usize,
}

fn radio_pair(max_frame_len: usize) -> (MemoryRadio, MemoryRadio) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    let sent = Arc::new(Mutex::new(VecDeque::new()));
    let notify = Arc::new(Notify::new());
    (
        MemoryRadio {
            peer: b_tx,
            inbound: a_rx,
            sent: Arc::clone(&sent),
            notify: Arc::clone(&notify),
            max_frame_len,
        },
        MemoryRadio {
            peer: a_tx,
            inbound: b_rx,
            sent,
            notify,
            max_frame_len,
        },
    )
}

impl PacketRadio for MemoryRadio {
    fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }

    fn send_frame(
        &self,
        frame: Vec<u8>,
    ) -> impl Future<Output = Result<Duration, TransmitError>> + Send {
        let peer = self.peer.clone();
        let sent = Arc::clone(&self.sent);
        let notify = Arc::clone(&self.notify);
        async move {
            sent.lock().unwrap().push_back(frame.clone());
            notify.notify_waiters();
            peer.send(frame).map_err(|_| TransmitError::Stopped)?;
            Ok(Duration::from_millis(1))
        }
    }

    fn recv_frame(&mut self) -> impl Future<Output = Option<Received>> + Send {
        async move {
            self.inbound.recv().await.map(|frame| Received {
                frame,
                rssi_dbm: -50,
                snr_db: 8.0,
            })
        }
    }
}

#[tokio::test]
async fn endpoint_announces_cross_the_tulle_packet_boundary() {
    let alice = Endpoint::new(PrivateIdentity::from_secret_bytes(&[0x11; 64]));
    let bob_id = PrivateIdentity::from_secret_bytes(&[0x22; 64]);
    let bob = Endpoint::new(bob_id.clone());
    let (alice_radio, bob_radio) = radio_pair(500);

    let alice_task = tokio::spawn(drive(alice.attach_interface(), alice_radio));
    let bob_task = tokio::spawn(drive(bob.attach_interface(), bob_radio));

    let name = DestinationName::new("bench", ["radio"]);
    let destination = name.destination_hash(bob_id.public());
    bob.announce(&name, b"tulle interface");

    let announce = tokio::time::timeout(Duration::from_secs(1), alice.next_announcement())
        .await
        .expect("announce crossed the radio")
        .expect("endpoint remains live");
    assert_eq!(announce.destination, destination);
    assert_eq!(announce.app_data, b"tulle interface");

    alice_task.abort();
    bob_task.abort();
}

#[tokio::test]
async fn physical_frame_limit_is_reported() {
    let endpoint = Endpoint::new(PrivateIdentity::from_secret_bytes(&[0x33; 64]));
    let (radio, _peer) = radio_pair(20);
    let interface = endpoint.attach_interface();
    let task = tokio::spawn(drive(interface, radio));

    endpoint.announce(
        &DestinationName::new("bench", ["oversize"]),
        b"larger than cap",
    );
    let error = task
        .await
        .expect("driver task")
        .expect_err("oversize packet must stop the interface");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}
