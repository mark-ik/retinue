//! The endpoint runtime: the tokio shell that turns the R0–R4 primitives into a working
//! peer.
//!
//! An [`Endpoint`] owns a TCP interface, an identity, and an [`AddressBook`]. A background
//! router reads packets and dispatches them: announces populate the address book, inbound
//! link requests are proved and surfaced as connections, and link data is routed to the
//! [`LinkStream`] for its link. Links are exposed as [`LinkStream`]s, which implement
//! [`AsyncRead`] + [`AsyncWrite`], so a consumer gets an ordinary bidirectional byte stream.
//!
//! This is the seam a host implements its own transport trait against; see the crate root.
//! It is deliberately point-to-point over one interface connection, which is the shape the
//! first consumer (mere) needs; multi-interface routing is a non-goal.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

use crate::address_book::AddressBook;
use crate::announce::{self, Announce, RAND_HASH_LEN};
use crate::destination::DestinationName;
use crate::hash::AddressHash;
use crate::iface::hdlc::{frame, Deframer};
use crate::identity::{Identity, PrivateIdentity};
use crate::link::{self, Inbound, Link, LinkMode, LinkTrailer};
use crate::packet::{Packet, PacketType};
use crate::token::IV_LEN;

/// Largest plaintext chunk per link data packet. Kept under `ENCRYPTED_MDU` (383) so the
/// encrypted token plus header always fits the MTU.
const WRITE_CHUNK: usize = crate::packet::ENCRYPTED_MDU - 16;

/// In-memory buffer for a stream's inbound side.
const DUPLEX_BUF: usize = 64 * 1024;

/// A bidirectional byte stream over a link.
///
/// Delegates [`AsyncRead`]/[`AsyncWrite`] to an internal duplex; a relay task chunks writes
/// into encrypted link data packets and the endpoint router feeds decrypted inbound data
/// back in. Dropping the stream ends its relay.
pub struct LinkStream {
    inner: DuplexStream,
    /// The link id, exposed for diagnostics.
    link_id: AddressHash,
}

impl LinkStream {
    /// The id of the link carrying this stream.
    pub fn link_id(&self) -> AddressHash {
        self.link_id
    }
}

impl AsyncRead for LinkStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for LinkStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A validated announce, surfaced to a consumer that needs the app_data binding (e.g. to
/// map an application-level peer id to a retinue destination).
#[derive(Clone, Debug)]
pub struct PeerAnnounce {
    /// The destination hash announced.
    pub destination: AddressHash,
    /// The announcing identity.
    pub identity: Identity,
    /// The app data the announce carried (a host binds its own peer id here).
    pub app_data: Vec<u8>,
}

/// An accepted inbound link and the destination it arrived on.
pub struct Accepted {
    /// The stream carrying the link.
    pub stream: LinkStream,
    /// The destination hash the link request targeted (an ALPN maps to one).
    pub destination: AddressHash,
}

/// A live link and the channel that feeds its stream inbound bytes.
struct LinkEntry {
    link: Link,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
}

type Links = Arc<Mutex<HashMap<AddressHash, LinkEntry>>>;

/// A destination this endpoint accepts links on.
struct Registered {
    dest: AddressHash,
}

/// Shared router state.
struct Shared {
    identity: PrivateIdentity,
    address_book: Mutex<AddressBook>,
    links: Links,
    registered: Mutex<Vec<Registered>>,
    outbound: mpsc::UnboundedSender<Packet>,
    /// Inbound accepted links (stream + destination), surfaced to `accept`.
    accepted_tx: mpsc::UnboundedSender<Accepted>,
    /// Validated announces, surfaced to `announcements`.
    announce_tx: mpsc::UnboundedSender<PeerAnnounce>,
    /// Pending outbound links awaiting a proof, keyed by destination: the waiter to wake,
    /// and the half-open link that verifies the proof.
    pending: Mutex<HashMap<AddressHash, oneshot::Sender<Link>>>,
    pending_links: Mutex<HashMap<AddressHash, link::PendingLink>>,
    /// A monotonic source of IV nonces. AES-CBC IVs must be unpredictable in production;
    /// the shell seeds this from the clock and the caller can substitute a CSPRNG.
    iv_seed: Mutex<u64>,
}

/// A Reticulum endpoint over one TCP interface connection.
pub struct Endpoint {
    shared: Arc<Shared>,
    accepted_rx: mpsc::UnboundedReceiver<Accepted>,
    announce_rx: mpsc::UnboundedReceiver<PeerAnnounce>,
}

impl Endpoint {
    /// Dial a peer's TCP interface and start the runtime.
    pub async fn connect(addr: SocketAddr, identity: PrivateIdentity) -> io::Result<Self> {
        Self::start(TcpStream::connect(addr).await?, identity)
    }

    /// Bind, accept one interface connection, and start the runtime.
    pub async fn bind(addr: SocketAddr, identity: PrivateIdentity) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let (stream, _) = listener.accept().await?;
        Self::start(stream, identity)
    }

    /// Bind and report the assigned address without accepting yet.
    pub async fn bind_addr(addr: SocketAddr) -> io::Result<(TcpListener, SocketAddr)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        Ok((listener, local))
    }

    /// Start the runtime on an accepted/dialed stream from [`bind_addr`](Self::bind_addr).
    pub fn from_listener_stream(stream: TcpStream, identity: PrivateIdentity) -> io::Result<Self> {
        Self::start(stream, identity)
    }

    fn start(stream: TcpStream, identity: PrivateIdentity) -> io::Result<Self> {
        let _ = stream.set_nodelay(true);
        let (mut read_half, mut write_half) = stream.into_split();

        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Packet>();
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<Accepted>();
        let (announce_tx, announce_rx) = mpsc::unbounded_channel::<PeerAnnounce>();

        let shared = Arc::new(Shared {
            identity,
            address_book: Mutex::new(AddressBook::new()),
            links: Arc::new(Mutex::new(HashMap::new())),
            registered: Mutex::new(Vec::new()),
            outbound: outbound_tx,
            accepted_tx,
            announce_tx,
            pending: Mutex::new(HashMap::new()),
            pending_links: Mutex::new(HashMap::new()),
            iv_seed: Mutex::new(seed_iv()),
        });

        // Writer task: frame and send outbound packets.
        tokio::spawn(async move {
            while let Some(pkt) = outbound_rx.recv().await {
                if write_half.write_all(&frame(&pkt.encode())).await.is_err() {
                    break;
                }
                let _ = write_half.flush().await;
            }
        });

        // Router task: read frames, decode, dispatch.
        let router = Arc::clone(&shared);
        tokio::spawn(async move {
            let mut deframer = Deframer::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = match read_half.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                for raw in deframer.push(&buf[..n]) {
                    if let Ok(pkt) = Packet::decode(&raw) {
                        route(&router, pkt);
                    }
                }
            }
        });

        Ok(Self {
            shared,
            accepted_rx,
            announce_rx,
        })
    }

    /// This endpoint's public identity.
    pub fn identity(&self) -> &Identity {
        self.shared.identity.public()
    }

    /// Register a destination to accept links on, and announce it.
    pub fn register(&self, name: DestinationName, app_data: &[u8]) {
        let dest = name.destination_hash(self.shared.identity.public());
        self.shared
            .registered
            .lock()
            .unwrap()
            .push(Registered { dest });
        self.announce(&name, app_data);
    }

    /// Emit an announce for a destination.
    pub fn announce(&self, name: &DestinationName, app_data: &[u8]) {
        let pkt = announce::build(
            &self.shared.identity,
            name.name_hash(),
            &rand_hash(&self.shared),
            None,
            app_data,
        );
        let _ = self.shared.outbound.send(pkt);
    }

    /// The address book, for resolving learned peers.
    pub fn resolve(&self, dest: AddressHash) -> Option<Identity> {
        self.shared
            .address_book
            .lock()
            .unwrap()
            .resolve(dest)
            .map(|p| p.identity)
    }

    /// Open a link to a destination and return its stream. `peer` is the destination's
    /// identity (learned from an announce, e.g. via [`resolve`](Self::resolve)).
    pub async fn open(&self, dest: AddressHash, peer: Identity) -> io::Result<LinkStream> {
        let ephemeral = ephemeral_seed(&self.shared);
        let (pending, request) = link::PendingLink::open(
            dest,
            peer,
            &ephemeral,
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: crate::packet::MTU as u32 },
        );

        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(pending.link_id(), tx);
        // Stash the pending link so the router can prove it.
        self.shared
            .pending_links
            .lock()
            .unwrap()
            .insert(pending.link_id(), pending);
        let _ = self.shared.outbound.send(request);

        let link = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "link setup dropped"))?;
        Ok(register_stream(&self.shared, link))
    }

    /// Wait for the next inbound link, surfaced as a stream.
    pub async fn accept(&mut self) -> io::Result<LinkStream> {
        Ok(self.accept_on_any().await?.stream)
    }

    /// Wait for the next inbound link, with the destination it targeted (an ALPN maps to a
    /// destination, so a host can dispatch by protocol).
    pub async fn accept_on_any(&mut self) -> io::Result<Accepted> {
        self.accepted_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed"))
    }

    /// The next validated announce, for building a host peer-id to destination map.
    pub async fn next_announcement(&mut self) -> io::Result<PeerAnnounce> {
        self.announce_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed"))
    }
}

/// Dispatch one inbound packet.
fn route(shared: &Arc<Shared>, pkt: Packet) {
    match pkt.packet_type {
        PacketType::Announce => {
            if let Ok(a) = Announce::decode(&pkt) {
                shared.address_book.lock().unwrap().ingest(&a);
                let _ = shared.announce_tx.send(PeerAnnounce {
                    destination: a.destination,
                    identity: a.identity,
                    app_data: a.app_data,
                });
            }
        }
        PacketType::LinkRequest => {
            let dest = pkt.destination;
            let is_ours = shared.registered.lock().unwrap().iter().any(|r| r.dest == dest);
            if is_ours {
                let ephemeral = ephemeral_seed(shared);
                if let Ok((link, proof)) = link::accept(
                    &pkt,
                    &shared.identity,
                    &ephemeral,
                    LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: crate::packet::MTU as u32 },
                ) {
                    let _ = shared.outbound.send(proof);
                    let stream = register_stream(shared, link);
                    let _ = shared.accepted_tx.send(Accepted { stream, destination: dest });
                }
            }
        }
        PacketType::Proof => {
            // Complete a pending outbound link.
            let maybe = shared.pending_links.lock().unwrap().remove(&pkt.destination);
            if let Some(pending) = maybe
                && let Ok(link) = pending.prove(&pkt)
                && let Some(tx) = shared.pending.lock().unwrap().remove(&pkt.destination)
            {
                let _ = tx.send(link);
            }
        }
        PacketType::Data => {
            // Link data: route to the matching stream.
            let entry_inbound = shared
                .links
                .lock()
                .unwrap()
                .get(&pkt.destination)
                .map(|e| (e.link.clone(), e.inbound.clone()));
            if let Some((link, inbound)) = entry_inbound
                && let Some(Inbound::Data(bytes)) = link.receive(&pkt)
            {
                let _ = inbound.send(bytes);
            }
        }
    }
}

/// Build a [`LinkStream`] for a live link, wiring up the inbound feed and the outbound
/// relay, and register the link so the router can route to it.
fn register_stream(shared: &Arc<Shared>, link: Link) -> LinkStream {
    let (mine, theirs) = tokio::io::duplex(DUPLEX_BUF);
    let (mut read_half, mut write_half) = tokio::io::split(theirs);
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let link_id = link.id();

    shared.links.lock().unwrap().insert(
        link_id,
        LinkEntry { link: link.clone(), inbound: inbound_tx },
    );

    // Inbound: decrypted data from the router → the stream's read side.
    tokio::spawn(async move {
        while let Some(bytes) = inbound_rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // Outbound: the stream's writes → encrypted link data packets.
    let out_link = link;
    let outbound = shared.outbound.clone();
    let iv_shared = Arc::clone(shared);
    tokio::spawn(async move {
        let mut buf = [0u8; WRITE_CHUNK];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let iv = next_iv(&iv_shared);
                    if outbound.send(out_link.data_packet(&buf[..n], &iv)).is_err() {
                        break;
                    }
                }
            }
        }
    });

    LinkStream { inner: mine, link_id }
}

fn rand_hash(shared: &Arc<Shared>) -> [u8; RAND_HASH_LEN] {
    let src = next_iv(shared); // 16 bytes, enough for the 10-byte rand hash
    let mut out = [0u8; RAND_HASH_LEN];
    out.copy_from_slice(&src[..RAND_HASH_LEN]);
    out
}

fn ephemeral_seed(shared: &Arc<Shared>) -> [u8; 64] {
    // A fresh 64-byte seed per link. Derived from the IV source; a production endpoint
    // should draw this from a CSPRNG, but it must only be unique+unpredictable per link.
    let mut seed = [0u8; 64];
    for chunk in seed.chunks_mut(8) {
        let v = next_u64(shared);
        chunk.copy_from_slice(&v.to_le_bytes()[..chunk.len()]);
    }
    seed
}

fn next_iv(shared: &Arc<Shared>) -> [u8; IV_LEN] {
    let a = next_u64(shared);
    let b = next_u64(shared);
    let mut iv = [0u8; IV_LEN];
    iv[..8].copy_from_slice(&a.to_le_bytes());
    iv[8..].copy_from_slice(&b.to_le_bytes());
    iv
}

fn next_u64(shared: &Arc<Shared>) -> u64 {
    let mut g = shared.iv_seed.lock().unwrap();
    // A small xorshift so successive values are not trivially sequential.
    let mut x = *g;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *g = x;
    x
}

fn seed_iv() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
    (n as u64) | 1
}
