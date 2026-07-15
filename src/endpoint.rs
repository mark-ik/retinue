//! The endpoint runtime: the tokio shell that turns the R0–R4 primitives into a working
//! peer.
//!
//! An [`Endpoint`] holds an identity, an [`AddressBook`], and any number of **interfaces**
//! (TCP connections, dialed or accepted). A background router reads packets from every
//! interface, tagged with the interface they arrived on, and dispatches them: announces
//! populate the address book, inbound link requests are proved and surfaced as connections,
//! and link data is routed to the [`LinkStream`] for its link. Announces are broadcast on
//! every interface; a link's traffic goes back out the interface it came in on. Links are
//! exposed as [`LinkStream`]s (`AsyncRead` + `AsyncWrite`), an ordinary bidirectional byte
//! stream.
//!
//! Multiple interfaces are the substrate for routing (a node that forwards between them) and
//! for a host transport reaching many peers. This is the seam a host implements its own
//! transport trait against; see the crate root.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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

/// Maximum hops an announce or packet may travel before a transport node drops it. RNS's
/// default `m` (`PATHFINDER_M`).
const MAX_HOPS: u8 = 128;

/// How many recent announce packet-hashes to remember for de-duplication.
const SEEN_ANNOUNCES: usize = 4096;

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
/// Identifies one attached interface (one TCP connection).
pub type InterfaceId = u32;

/// An attached interface: the channel its writer task drains.
struct Iface {
    id: InterfaceId,
    outbound: mpsc::UnboundedSender<Packet>,
}

struct LinkEntry {
    link: Link,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
    /// The interface this link's traffic goes out on. Recorded for routing (R7), where a
    /// forwarded link's return traffic must go back the way it came.
    #[allow(dead_code)]
    iface: InterfaceId,
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
    /// Every attached interface. Announces broadcast to all; link traffic targets one.
    interfaces: Mutex<Vec<Iface>>,
    /// The router's inbound channel: every interface's reader feeds `(interface, packet)`.
    router_tx: mpsc::UnboundedSender<(InterfaceId, Packet)>,
    /// Inbound accepted links (stream + destination), surfaced to `accept`.
    accepted_tx: mpsc::UnboundedSender<Accepted>,
    /// Validated announces, surfaced to `announcements`.
    announce_tx: mpsc::UnboundedSender<PeerAnnounce>,
    /// Pending outbound links awaiting a proof, keyed by destination: the waiter to wake
    /// (with the interface the proof came in on), and the half-open link that verifies it.
    pending: Mutex<HashMap<AddressHash, oneshot::Sender<(Link, InterfaceId)>>>,
    pending_links: Mutex<HashMap<AddressHash, link::PendingLink>>,
    /// A monotonic source of IV nonces. AES-CBC IVs must be unpredictable in production;
    /// the shell seeds this from the clock and the caller can substitute a CSPRNG.
    iv_seed: Mutex<u64>,
    next_iface_id: AtomicU32,
    /// Whether this endpoint acts as a transport node (forwards announces and packets).
    routing: AtomicBool,
    /// Learned routes: destination → the interface to reach it and its hop count. Populated
    /// from announces.
    path_table: Mutex<HashMap<AddressHash, PathEntry>>,
    /// Recently-seen announce packet hashes, for de-duplication (a ring of the last
    /// [`SEEN_ANNOUNCES`]).
    seen_announces: Mutex<(HashSet<AddressHash>, VecDeque<AddressHash>)>,
}

/// A learned route to a destination.
#[derive(Clone, Copy)]
struct PathEntry {
    iface: InterfaceId,
    hops: u8,
}

impl Shared {
    /// Send a packet out every interface (announces, path requests).
    fn broadcast(&self, pkt: Packet) {
        for i in self.interfaces.lock().unwrap().iter() {
            let _ = i.outbound.send(pkt.clone());
        }
    }

    /// Send a packet out every interface except one (announce forwarding: never back the
    /// way it came).
    fn broadcast_except(&self, except: InterfaceId, pkt: Packet) {
        for i in self.interfaces.lock().unwrap().iter() {
            if i.id != except {
                let _ = i.outbound.send(pkt.clone());
            }
        }
    }

    /// Send a packet out one interface.
    fn send_on(&self, iface: InterfaceId, pkt: Packet) {
        if let Some(i) = self.interfaces.lock().unwrap().iter().find(|i| i.id == iface) {
            let _ = i.outbound.send(pkt);
        }
    }

    /// Record that `dest` is reachable via `iface` at `hops`, keeping the shortest route.
    fn learn_path(&self, dest: AddressHash, iface: InterfaceId, hops: u8) {
        let mut t = self.path_table.lock().unwrap();
        match t.get(&dest) {
            Some(e) if e.hops <= hops => {}
            _ => {
                t.insert(dest, PathEntry { iface, hops });
            }
        }
    }

    /// Whether this announce (by packet hash) is new; records it if so.
    fn announce_is_new(&self, hash: AddressHash) -> bool {
        let mut g = self.seen_announces.lock().unwrap();
        if g.0.contains(&hash) {
            return false;
        }
        g.0.insert(hash);
        g.1.push_back(hash);
        if g.1.len() > SEEN_ANNOUNCES
            && let Some(old) = g.1.pop_front()
        {
            g.0.remove(&old);
        }
        true
    }
}

/// A Reticulum endpoint over any number of interfaces.
pub struct Endpoint {
    shared: Arc<Shared>,
    accepted_rx: mpsc::UnboundedReceiver<Accepted>,
    announce_rx: mpsc::UnboundedReceiver<PeerAnnounce>,
}

impl Endpoint {
    /// Create an endpoint with no interfaces yet, and start its router.
    pub fn new(identity: PrivateIdentity) -> Self {
        let (router_tx, mut router_rx) = mpsc::unbounded_channel::<(InterfaceId, Packet)>();
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<Accepted>();
        let (announce_tx, announce_rx) = mpsc::unbounded_channel::<PeerAnnounce>();

        let shared = Arc::new(Shared {
            identity,
            address_book: Mutex::new(AddressBook::new()),
            links: Arc::new(Mutex::new(HashMap::new())),
            registered: Mutex::new(Vec::new()),
            interfaces: Mutex::new(Vec::new()),
            router_tx,
            accepted_tx,
            announce_tx,
            pending: Mutex::new(HashMap::new()),
            pending_links: Mutex::new(HashMap::new()),
            iv_seed: Mutex::new(seed_iv()),
            next_iface_id: AtomicU32::new(0),
            routing: AtomicBool::new(false),
            path_table: Mutex::new(HashMap::new()),
            seen_announces: Mutex::new((HashSet::new(), VecDeque::new())),
        });

        let router = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Some((iface, pkt)) = router_rx.recv().await {
                route(&router, iface, pkt);
            }
        });

        Self {
            shared,
            accepted_rx,
            announce_rx,
        }
    }

    /// Create an endpoint and dial one TCP peer as its first interface.
    pub async fn connect(addr: SocketAddr, identity: PrivateIdentity) -> io::Result<Self> {
        let ep = Self::new(identity);
        ep.attach_tcp_client(addr).await?;
        Ok(ep)
    }

    /// Attach a connected TCP stream as an interface, and return its id.
    pub fn attach_stream(&self, stream: TcpStream) -> InterfaceId {
        attach(&self.shared, stream)
    }

    /// Dial a TCP peer and attach it as an interface.
    pub async fn attach_tcp_client(&self, addr: SocketAddr) -> io::Result<InterfaceId> {
        Ok(attach(&self.shared, TcpStream::connect(addr).await?))
    }

    /// Listen on TCP; every accepted connection becomes an interface. Returns the bound
    /// address (pass port 0 to get an OS-assigned one).
    pub async fn listen_tcp(&self, addr: SocketAddr) -> io::Result<SocketAddr> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                attach(&shared, stream);
            }
        });
        Ok(local)
    }

    /// Number of interfaces currently attached.
    pub fn interface_count(&self) -> usize {
        self.shared.interfaces.lock().unwrap().len()
    }

    /// Act as a transport node: forward announces (hops+1, de-duplicated, never back the way
    /// they came) and forward packets toward learned destinations. Off by default, since an
    /// endpoint carries only its own traffic unless it opts in.
    pub fn enable_routing(&self) {
        self.shared.routing.store(true, Ordering::Relaxed);
    }

    /// The interface a learned destination is reachable over, and its hop count.
    pub fn route_to(&self, dest: AddressHash) -> Option<(InterfaceId, u8)> {
        self.shared
            .path_table
            .lock()
            .unwrap()
            .get(&dest)
            .map(|e| (e.iface, e.hops))
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

    /// Emit an announce for a destination on every interface.
    pub fn announce(&self, name: &DestinationName, app_data: &[u8]) {
        let pkt = announce::build(
            &self.shared.identity,
            name.name_hash(),
            &rand_hash(&self.shared),
            None,
            app_data,
        );
        self.shared.broadcast(pkt);
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
        // Broadcast the request; the peer responds on whichever interface it is reachable
        // over, and the link binds to that interface.
        self.shared.broadcast(request);

        let (link, iface) = rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::ConnectionReset, "link setup dropped"))?;
        Ok(register_stream(&self.shared, link, iface))
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

/// Attach a connected stream as an interface: register it, and spawn its writer and reader
/// tasks (the reader feeds the shared router, tagged with the interface id).
fn attach(shared: &Arc<Shared>, stream: TcpStream) -> InterfaceId {
    let _ = stream.set_nodelay(true);
    let id = shared.next_iface_id.fetch_add(1, Ordering::Relaxed);
    let (mut read_half, mut write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Packet>();
    shared.interfaces.lock().unwrap().push(Iface { id, outbound: out_tx });

    // Writer: frame and send this interface's outbound packets.
    tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if write_half.write_all(&frame(&pkt.encode())).await.is_err() {
                break;
            }
            let _ = write_half.flush().await;
        }
    });

    // Reader: deframe, decode, hand to the router tagged with this interface.
    let router_tx = shared.router_tx.clone();
    tokio::spawn(async move {
        let mut deframer = Deframer::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            for raw in deframer.push(&buf[..n]) {
                if let Ok(pkt) = Packet::decode(&raw)
                    && router_tx.send((id, pkt)).is_err()
                {
                    return;
                }
            }
        }
    });

    id
}

/// Dispatch one inbound packet that arrived on `iface`.
fn route(shared: &Arc<Shared>, iface: InterfaceId, pkt: Packet) {
    match pkt.packet_type {
        PacketType::Announce => {
            if let Ok(a) = Announce::decode(&pkt) {
                shared.address_book.lock().unwrap().ingest(&a);
                shared.learn_path(a.destination, iface, pkt.hops);
                let _ = shared.announce_tx.send(PeerAnnounce {
                    destination: a.destination,
                    identity: a.identity,
                    app_data: a.app_data,
                });
                // As a transport node, propagate the announce onward: hops+1, out every
                // other interface, once per announce (de-duplicated by packet hash).
                if shared.routing.load(Ordering::Relaxed)
                    && pkt.hops < MAX_HOPS
                    && shared.announce_is_new(pkt.hash())
                {
                    let mut fwd = pkt;
                    fwd.hops += 1;
                    shared.broadcast_except(iface, fwd);
                }
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
                    shared.send_on(iface, proof);
                    let stream = register_stream(shared, link, iface);
                    let _ = shared.accepted_tx.send(Accepted { stream, destination: dest });
                }
            }
        }
        PacketType::Proof => {
            // Complete a pending outbound link, binding it to the interface it came in on.
            let maybe = shared.pending_links.lock().unwrap().remove(&pkt.destination);
            if let Some(pending) = maybe
                && let Ok(link) = pending.prove(&pkt)
                && let Some(tx) = shared.pending.lock().unwrap().remove(&pkt.destination)
            {
                let _ = tx.send((link, iface));
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

/// Build a [`LinkStream`] for a live link on `iface`, wiring the inbound feed and the
/// outbound relay, and register the link so the router can route to it.
fn register_stream(shared: &Arc<Shared>, link: Link, iface: InterfaceId) -> LinkStream {
    let (mine, theirs) = tokio::io::duplex(DUPLEX_BUF);
    let (mut read_half, mut write_half) = tokio::io::split(theirs);
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let link_id = link.id();

    shared.links.lock().unwrap().insert(
        link_id,
        LinkEntry { link: link.clone(), inbound: inbound_tx, iface },
    );

    // Inbound: decrypted data from the router → the stream's read side.
    tokio::spawn(async move {
        while let Some(bytes) = inbound_rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });

    // Outbound: the stream's writes → encrypted link data packets, out the link's interface.
    let out_link = link;
    let iv_shared = Arc::clone(shared);
    tokio::spawn(async move {
        let mut buf = [0u8; WRITE_CHUNK];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let iv = next_iv(&iv_shared);
                    iv_shared.send_on(iface, out_link.data_packet(&buf[..n], &iv));
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
