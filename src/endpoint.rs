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
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

use crate::address_book::AddressBook;
use crate::announce::{self, Announce, RAND_HASH_LEN};
use crate::destination::DestinationName;
use crate::hash::AddressHash;
use crate::iface::hdlc::{frame, Deframer};
use crate::identity::{Identity, PrivateIdentity};
use crate::link::{self, CTX_CHANNEL, CTX_LINKCLOSE, Inbound, Link, LinkMode, LinkTrailer};
use crate::packet::{Packet, PacketType};
use crate::reliable::ReliableChannel;
use crate::token::IV_LEN;

/// Largest plaintext chunk per link data packet. Kept under `ENCRYPTED_MDU` (383) so the
/// encrypted token plus header always fits the MTU.
const WRITE_CHUNK: usize = crate::packet::ENCRYPTED_MDU - 16;

/// In-memory buffer for a stream's inbound side.
const DUPLEX_BUF: usize = 64 * 1024;

/// The reliable driver's clock period. It advances a logical tick each period, which drives
/// retransmission of unproven channel packets (`DEFAULT_RETX_TIMEOUT` ticks). One timer per
/// active reliable link; a production build would pause it when the link is fully idle.
const RELIABLE_TICK_MS: u64 = 50;

/// How long [`Endpoint::open`] waits for a link proof before giving up. Multi-hop setup can
/// be slow, so this is generous; it exists to bound a setup that will otherwise never
/// complete (a peer that never proves) rather than to hang the caller forever.
const LINK_SETUP_TIMEOUT: Duration = Duration::from_secs(15);

/// Depth of the router's inbound queue. Bounded so a flooding peer cannot make the endpoint
/// buffer packets without limit: a TCP reader awaits when it is full (back-pressuring the
/// socket, so the flow control reaches the peer), and the [`InterfaceSink::deliver`] seam,
/// which cannot await, drops instead.
const ROUTER_QUEUE: usize = 1024;

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

/// A raw packet interface: the seam every transport plugs into.
///
/// The endpoint sends outbound [`Packet`]s to it (drain [`next_outbound`]) and
/// receives inbound packets from it (via its [`InterfaceSink`]). Nothing here does
/// I/O or framing — the caller owns how bytes move. TCP's interface is exactly this
/// seam plus HDLC framing over a socket; a serial line, or a test loss-oracle that
/// drops/delays/reorders packets, is the same seam with a different pump.
///
/// [`next_outbound`]: Interface::next_outbound
pub struct Interface {
    id: InterfaceId,
    outbound: mpsc::UnboundedReceiver<Packet>,
    router_tx: mpsc::Sender<(InterfaceId, Packet)>,
}

impl Interface {
    /// This interface's id.
    pub fn id(&self) -> InterfaceId {
        self.id
    }

    /// The next packet the endpoint wants to send out this interface. `None` once
    /// the endpoint is dropped.
    pub async fn next_outbound(&mut self) -> Option<Packet> {
        self.outbound.recv().await
    }

    /// A cloneable handle for delivering packets received on this interface into
    /// the endpoint's router.
    pub fn sink(&self) -> InterfaceSink {
        InterfaceSink {
            id: self.id,
            router_tx: self.router_tx.clone(),
        }
    }

    /// Split into the outbound packet stream and an inbound [`InterfaceSink`], the
    /// usual shape for a bidirectional pump.
    pub fn split(self) -> (mpsc::UnboundedReceiver<Packet>, InterfaceSink) {
        let sink = InterfaceSink {
            id: self.id,
            router_tx: self.router_tx,
        };
        (self.outbound, sink)
    }
}

/// Delivers packets received on an [`Interface`] into the endpoint's router,
/// tagged with the interface they arrived on.
#[derive(Clone)]
pub struct InterfaceSink {
    id: InterfaceId,
    router_tx: mpsc::Sender<(InterfaceId, Packet)>,
}

impl InterfaceSink {
    /// Deliver a received packet into the router. Returns `false` if the endpoint
    /// has been dropped.
    pub fn deliver(&self, pkt: Packet) -> bool {
        self.router_tx.try_send((self.id, pkt)).is_ok()
    }
}

/// An attached interface: the channel its writer task drains.
struct Iface {
    id: InterfaceId,
    outbound: mpsc::UnboundedSender<Packet>,
}

struct LinkEntry {
    link: Link,
    /// How inbound traffic for this link is handled: best-effort delivers decrypted bytes
    /// straight to the stream; reliable hands raw channel and proof packets to a driver.
    kind: LinkKind,
    /// The interface this link's traffic goes out on. Recorded for routing (R7), where a
    /// forwarded link's return traffic must go back the way it came.
    #[allow(dead_code)]
    iface: InterfaceId,
}

/// The delivery discipline of a link's stream, chosen when the stream is registered.
enum LinkKind {
    /// The router decrypts each data packet and forwards the plaintext (right for TCP,
    /// where the medium never drops).
    BestEffort {
        inbound: mpsc::UnboundedSender<Vec<u8>>,
    },
    /// The router forwards raw channel-data and proof packets to the reliable driver task,
    /// which orders them, proves receipts, and drives retransmission (for lossy media).
    Reliable {
        packets: mpsc::UnboundedSender<Packet>,
    },
}

type Links = Arc<Mutex<HashMap<AddressHash, LinkEntry>>>;

/// A destination this endpoint accepts links on.
struct Registered {
    dest: AddressHash,
    /// Whether links to it are reliable (Channel/Buffer + proofs) or best-effort.
    reliable: bool,
}

/// An accepted inbound **reliable** link, handed to [`Endpoint::accept_reliable`] to bind a
/// [`ReliableChannel`] once the caller supplies the peer identity to validate proofs against.
struct AcceptedLink {
    link: Link,
    iface: InterfaceId,
    /// The destination the link targeted. Kept for parity with [`Accepted`] and future
    /// per-destination reliable dispatch; `accept_reliable` does not surface it yet.
    #[allow(dead_code)]
    destination: AddressHash,
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
    router_tx: mpsc::Sender<(InterfaceId, Packet)>,
    /// Inbound accepted links (stream + destination), surfaced to `accept`.
    accepted_tx: mpsc::UnboundedSender<Accepted>,
    /// Inbound accepted reliable links, surfaced to `accept_reliable` (which binds the
    /// stream once given the peer identity to validate proofs against).
    reliable_accepted_tx: mpsc::UnboundedSender<AcceptedLink>,
    /// Validated announces, surfaced to `announcements`.
    announce_tx: mpsc::UnboundedSender<PeerAnnounce>,
    /// Pending outbound links awaiting a proof, keyed by destination: the waiter to wake
    /// (with the interface the proof came in on), and the half-open link that verifies it.
    pending: Mutex<HashMap<AddressHash, oneshot::Sender<(Link, InterfaceId)>>>,
    pending_links: Mutex<HashMap<AddressHash, link::PendingLink>>,
    next_iface_id: AtomicU32,
    /// Whether this endpoint acts as a transport node (forwards announces and packets).
    routing: AtomicBool,
    /// Learned routes: destination → the interface to reach it and its hop count. Populated
    /// from announces.
    path_table: Mutex<HashMap<AddressHash, PathEntry>>,
    /// Recently-seen announce packet hashes, for de-duplication (a ring of the last
    /// [`SEEN_ANNOUNCES`]).
    seen_announces: Mutex<(HashSet<AddressHash>, VecDeque<AddressHash>)>,
    /// The transport node reachable on each interface (its identity hash), learned from the
    /// `transport` field of header-type-2 announces. Packets sent out an interface with a
    /// transport node are addressed header-type-2 `[transport][dest]` so the node forwards
    /// them.
    iface_transport: Mutex<HashMap<InterfaceId, AddressHash>>,
    /// Links being forwarded through us (this node is a transport hop): a link id maps to the
    /// two interfaces it bridges, so a proof or link data arriving on one goes out the other.
    link_transport: Mutex<HashMap<AddressHash, (InterfaceId, InterfaceId)>>,
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

    /// Send a packet out one interface, addressed through that interface's transport node if
    /// it has one (header-type-2 `[transport][dest]`), so a transport node forwards it.
    fn send_on(&self, iface: InterfaceId, pkt: Packet) {
        let addressed = self.address_for(iface, pkt);
        if let Some(i) = self.interfaces.lock().unwrap().iter().find(|i| i.id == iface) {
            let _ = i.outbound.send(addressed);
        }
    }

    /// Wrap a packet for the interface it will go out on: if that interface reaches a
    /// transport node, make it header-type-2 with the node's id in the transport field so the
    /// node forwards it toward `destination`. A directly-connected interface leaves it as is.
    fn address_for(&self, iface: InterfaceId, mut pkt: Packet) -> Packet {
        if let Some(t) = self.iface_transport.lock().unwrap().get(&iface).copied() {
            pkt.header_type = crate::packet::HeaderType::Type2;
            pkt.transport = Some(t);
        }
        pkt
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
///
/// All methods take `&self` (the receivers are behind async mutexes), so an endpoint can be
/// wrapped in an `Arc` and shared: a host transport can call `open`/`announce` from one task
/// while another drives `accept`/`next_announcement`.
pub struct Endpoint {
    shared: Arc<Shared>,
    accepted_rx: AsyncMutex<mpsc::UnboundedReceiver<Accepted>>,
    reliable_accepted_rx: AsyncMutex<mpsc::UnboundedReceiver<AcceptedLink>>,
    announce_rx: AsyncMutex<mpsc::UnboundedReceiver<PeerAnnounce>>,
}

impl Endpoint {
    /// Create an endpoint with no interfaces yet, and start its router.
    pub fn new(identity: PrivateIdentity) -> Self {
        let (router_tx, mut router_rx) = mpsc::channel::<(InterfaceId, Packet)>(ROUTER_QUEUE);
        let (accepted_tx, accepted_rx) = mpsc::unbounded_channel::<Accepted>();
        let (reliable_accepted_tx, reliable_accepted_rx) = mpsc::unbounded_channel::<AcceptedLink>();
        let (announce_tx, announce_rx) = mpsc::unbounded_channel::<PeerAnnounce>();

        let shared = Arc::new(Shared {
            identity,
            address_book: Mutex::new(AddressBook::new()),
            links: Arc::new(Mutex::new(HashMap::new())),
            registered: Mutex::new(Vec::new()),
            interfaces: Mutex::new(Vec::new()),
            router_tx,
            accepted_tx,
            reliable_accepted_tx,
            announce_tx,
            pending: Mutex::new(HashMap::new()),
            pending_links: Mutex::new(HashMap::new()),
            next_iface_id: AtomicU32::new(0),
            routing: AtomicBool::new(false),
            path_table: Mutex::new(HashMap::new()),
            seen_announces: Mutex::new((HashSet::new(), VecDeque::new())),
            iface_transport: Mutex::new(HashMap::new()),
            link_transport: Mutex::new(HashMap::new()),
        });

        let router = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Some((iface, pkt)) = router_rx.recv().await {
                route(&router, iface, pkt);
            }
        });

        Self {
            shared,
            accepted_rx: AsyncMutex::new(accepted_rx),
            reliable_accepted_rx: AsyncMutex::new(reliable_accepted_rx),
            announce_rx: AsyncMutex::new(announce_rx),
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

    /// Attach a raw packet [`Interface`] and return its handle, doing no I/O or
    /// framing. The caller drives the transport: drain [`Interface::next_outbound`]
    /// to send packets, and call the [`InterfaceSink`] to deliver received ones.
    /// This is the seam a non-TCP medium (serial, or a deterministic test loss
    /// oracle) plugs into; `attach_tcp_client` / `listen_tcp` are this plus framing.
    pub fn attach_interface(&self) -> Interface {
        let id = self.shared.next_iface_id.fetch_add(1, Ordering::Relaxed);
        let (out_tx, out_rx) = mpsc::unbounded_channel::<Packet>();
        self.shared
            .interfaces
            .lock()
            .unwrap()
            .push(Iface { id, outbound: out_tx });
        Interface {
            id,
            outbound: out_rx,
            router_tx: self.shared.router_tx.clone(),
        }
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

    /// Register a destination to accept best-effort links on, and announce it. Accept these
    /// with [`accept`](Self::accept).
    pub fn register(&self, name: DestinationName, app_data: &[u8]) {
        self.register_with(name, app_data, false);
    }

    /// Register a destination to accept **reliable** links on — the Channel/Buffer path with
    /// proof acks, for lossy interfaces — and announce it. Accept these with
    /// [`accept_reliable`](Self::accept_reliable), supplying the peer identity whose proofs
    /// to validate.
    pub fn register_reliable(&self, name: DestinationName, app_data: &[u8]) {
        self.register_with(name, app_data, true);
    }

    fn register_with(&self, name: DestinationName, app_data: &[u8], reliable: bool) {
        let dest = name.destination_hash(self.shared.identity.public());
        self.shared
            .registered
            .lock()
            .unwrap()
            .push(Registered { dest, reliable });
        self.announce(&name, app_data);
    }

    /// Emit an announce for a destination on every interface.
    pub fn announce(&self, name: &DestinationName, app_data: &[u8]) {
        let pkt = announce::build(
            &self.shared.identity,
            name.name_hash(),
            &rand_hash(),
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

    /// Open a best-effort link to a destination and return its stream. `peer` is the
    /// destination's identity (learned from an announce, e.g. via [`resolve`](Self::resolve)).
    pub async fn open(&self, dest: AddressHash, peer: Identity) -> io::Result<LinkStream> {
        let (link, iface) = self.establish(dest, peer).await?;
        Ok(register_stream(&self.shared, link, iface))
    }

    /// Open a **reliable** link to a destination — the Channel/Buffer path with proof acks,
    /// for lossy interfaces — and return its stream. `peer` is the destination's identity:
    /// the handshake authenticates it, and the peer's proofs of our packets are validated
    /// against it.
    pub async fn open_reliable(&self, dest: AddressHash, peer: Identity) -> io::Result<LinkStream> {
        let (link, iface) = self.establish(dest, peer).await?;
        Ok(register_reliable_stream(&self.shared, link, iface, peer))
    }

    /// Establish a link to `dest` (whose identity is `peer`), returning it with the interface
    /// its proof arrived on. The stream discipline is chosen by the caller.
    async fn establish(&self, dest: AddressHash, peer: Identity) -> io::Result<(Link, InterfaceId)> {
        let ephemeral = ephemeral_seed();
        let (pending, request) = link::PendingLink::open(
            dest,
            peer,
            &ephemeral,
            LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: crate::packet::MTU as u32 },
        );

        let link_id = pending.link_id();
        let (tx, rx) = oneshot::channel();
        self.shared.pending.lock().unwrap().insert(link_id, tx);
        // Stash the pending link so the router can prove it.
        self.shared.pending_links.lock().unwrap().insert(link_id, pending);
        // If setup does not complete — it times out below, or the caller drops this future —
        // remove both entries on the way out so a failed setup never leaks router state.
        let mut guard = PendingGuard { shared: Arc::clone(&self.shared), link_id, armed: true };

        // Send the request toward the destination: on the interface the path table names
        // (addressed via its transport node if remote), or broadcast if we have no route yet
        // (a directly-connected peer).
        match self.shared.path_table.lock().unwrap().get(&dest).map(|e| e.iface) {
            Some(iface) => self.shared.send_on(iface, request),
            None => self.shared.broadcast(request),
        }

        match tokio::time::timeout(LINK_SETUP_TIMEOUT, rx).await {
            Ok(Ok(established)) => {
                guard.armed = false; // the router already removed both entries on success
                Ok(established)
            }
            Ok(Err(_)) => Err(io::Error::new(io::ErrorKind::ConnectionReset, "link setup dropped")),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "link setup timed out")),
        }
    }

    /// Wait for the next inbound link, surfaced as a stream.
    pub async fn accept(&self) -> io::Result<LinkStream> {
        Ok(self.accept_on_any().await?.stream)
    }

    /// Wait for the next inbound link, with the destination it targeted (an ALPN maps to a
    /// destination, so a host can dispatch by protocol).
    pub async fn accept_on_any(&self) -> io::Result<Accepted> {
        self.accepted_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed"))
    }

    /// Wait for the next inbound **reliable** link (to a destination registered with
    /// [`register_reliable`](Self::register_reliable)) and bind its stream. `peer` is the
    /// initiator's identity, whose proofs of our sent packets this side validates against.
    ///
    /// The initiator's identity is not yet carried on the link (an `identify` step is a
    /// follow-on), so the caller supplies the expected `peer` here — a retinue peer whose
    /// identity is known out of band, or from its announce.
    pub async fn accept_reliable(&self, peer: Identity) -> io::Result<LinkStream> {
        let accepted = self
            .reliable_accepted_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "endpoint closed"))?;
        Ok(register_reliable_stream(&self.shared, accepted.link, accepted.iface, peer))
    }

    /// The next validated announce, for building a host peer-id to destination map.
    pub async fn next_announcement(&self) -> io::Result<PeerAnnounce> {
        self.announce_rx
            .lock()
            .await
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
                // Await on a full router queue rather than dropping: this back-pressures the
                // socket read, so TCP flow control slows a flooding peer. `send` errors only
                // when the router is gone, which means the endpoint is shutting down.
                if let Ok(pkt) = Packet::decode(&raw)
                    && router_tx.send((id, pkt)).await.is_err()
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
    // Transport-node forwarding (announces are re-forwarded in their own arm instead, so
    // they still populate our address book).
    if pkt.packet_type != PacketType::Announce && shared.routing.load(Ordering::Relaxed) {
        // A packet whose destination is a link we bridge goes to the opposite side, whatever
        // its header type: the two endpoints may address it differently (one type-2 through
        // us, one type-1 direct, e.g. a responder that never learned it is behind us).
        let bridged = shared.link_transport.lock().unwrap().get(&pkt.destination).copied();
        if let Some((a, b)) = bridged {
            forward_on(shared, if iface == a { b } else { a }, pkt);
            return;
        }
        // A header-type-2 packet addressed to us as the transport hop: forward toward its
        // destination (and record a bridge if it is a link request).
        if pkt.header_type == crate::packet::HeaderType::Type2
            && pkt.transport == Some(shared.identity.public().hash())
        {
            forward(shared, iface, pkt);
            return;
        }
    }
    match pkt.packet_type {
        PacketType::Announce => {
            if let Ok(a) = Announce::decode(&pkt) {
                shared.address_book.lock().unwrap().ingest(&a);
                shared.learn_path(a.destination, iface, pkt.hops);
                // A header-type-2 announce names the transport node forwarding it; remember
                // it as this interface's next hop so we can reach the destination through it.
                if let Some(t) = pkt.transport {
                    shared.iface_transport.lock().unwrap().insert(iface, t);
                }
                let _ = shared.announce_tx.send(PeerAnnounce {
                    destination: a.destination,
                    identity: a.identity,
                    app_data: a.app_data,
                });
                // As a transport node, propagate the announce onward: hops+1, stamped with
                // our identity as the transport node so downstream peers address replies
                // through us, out every other interface, de-duplicated by packet hash.
                if shared.routing.load(Ordering::Relaxed)
                    && pkt.hops < MAX_HOPS
                    && shared.announce_is_new(pkt.hash())
                {
                    let mut fwd = pkt;
                    fwd.hops += 1;
                    fwd.header_type = crate::packet::HeaderType::Type2;
                    fwd.transport = Some(shared.identity.public().hash());
                    shared.broadcast_except(iface, fwd);
                }
            }
        }
        PacketType::LinkRequest => {
            let dest = pkt.destination;
            let reliable = shared
                .registered
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.dest == dest)
                .map(|r| r.reliable);
            if let Some(reliable) = reliable {
                let ephemeral = ephemeral_seed();
                if let Ok((link, proof)) = link::accept(
                    &pkt,
                    &shared.identity,
                    &ephemeral,
                    LinkTrailer { mode: LinkMode::Aes256Cbc, mtu: crate::packet::MTU as u32 },
                ) {
                    shared.send_on(iface, proof);
                    if reliable {
                        // Defer the stream: accept_reliable binds it once given the peer
                        // identity to validate proofs against.
                        let _ = shared
                            .reliable_accepted_tx
                            .send(AcceptedLink { link, iface, destination: dest });
                    } else {
                        let stream = register_stream(shared, link, iface);
                        let _ = shared.accepted_tx.send(Accepted { stream, destination: dest });
                    }
                }
            }
        }
        PacketType::Proof => {
            // Complete a pending outbound link, binding it to the interface it came in on.
            // Validate the proof against the pending link BEFORE removing it: a forged proof
            // addressed to a real pending link id must not be able to evict it and strand the
            // genuine proof that follows. Only a proof that actually verifies removes it.
            let proved = {
                let mut pend = shared.pending_links.lock().unwrap();
                let link = pend.get(&pkt.destination).and_then(|p| p.prove(&pkt).ok());
                if link.is_some() {
                    pend.remove(&pkt.destination);
                }
                link
            };
            if let Some(link) = proved {
                if let Some(tx) = shared.pending.lock().unwrap().remove(&pkt.destination) {
                    let _ = tx.send((link, iface));
                }
            } else {
                // Otherwise a link-data proof for an established link: hand it to the
                // reliable driver, which matches its hash to an outstanding sequence.
                // Best-effort links never request proofs, so there is nothing to do.
                let packets = shared.links.lock().unwrap().get(&pkt.destination).and_then(|e| {
                    match &e.kind {
                        LinkKind::Reliable { packets } => Some(packets.clone()),
                        LinkKind::BestEffort { .. } => None,
                    }
                });
                if let Some(packets) = packets {
                    let _ = packets.send(pkt);
                }
            }
        }
        PacketType::Data => {
            // Link data: route to the matching stream by its delivery discipline. Clone the
            // sender(s) under the lock, then act on the packet once the lock is released.
            let (reliable, best) = {
                let links = shared.links.lock().unwrap();
                match links.get(&pkt.destination) {
                    Some(e) => match &e.kind {
                        LinkKind::Reliable { packets } => (Some(packets.clone()), None),
                        LinkKind::BestEffort { inbound } => (None, Some((e.link.clone(), inbound.clone()))),
                    },
                    None => (None, None),
                }
            };
            if let Some(packets) = reliable {
                // The reliable driver owns decryption, ordering, and proving; hand it raw.
                let _ = packets.send(pkt);
            } else if let Some((link, inbound)) = best {
                match link.receive(&pkt) {
                    Some(Inbound::Data(bytes)) => {
                        let _ = inbound.send(bytes);
                    }
                    Some(Inbound::Close) => {
                        // The peer closed the link: drop its entry so the inbound
                        // sender is released. The stream's inbound relay then ends
                        // and the local reader sees EOF (what read-to-end needs).
                        shared.links.lock().unwrap().remove(&pkt.destination);
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Forward a header-type-2 packet addressed to us as a transport hop, toward its
/// destination. `from` is the interface it arrived on.
fn forward(shared: &Arc<Shared>, from: InterfaceId, pkt: Packet) {
    if pkt.hops >= MAX_HOPS {
        return;
    }
    let dest = pkt.destination;

    // Route toward the destination by the path table.
    let next = shared.path_table.lock().unwrap().get(&dest).map(|e| e.iface);
    if let Some(out) = next {
        // A link request establishes a bridge: record the link id's two interfaces so the
        // proof and subsequent link data forward back the way they came.
        if pkt.packet_type == PacketType::LinkRequest
            && let Ok(link_id) = link::link_id(&pkt)
        {
            shared
                .link_transport
                .lock()
                .unwrap()
                .insert(link_id, (from, out));
        }
        forward_on(shared, out, pkt);
    }
}

/// Re-address a forwarded packet for the interface it leaves on (stripping our transport
/// stamp, so `send_on` re-adds the next hop's if there is one), bump hops, and send.
fn forward_on(shared: &Arc<Shared>, out: InterfaceId, mut pkt: Packet) {
    pkt.hops += 1;
    pkt.header_type = crate::packet::HeaderType::Type1;
    pkt.transport = None;
    shared.send_on(out, pkt);
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
        LinkEntry { link: link.clone(), kind: LinkKind::BestEffort { inbound: inbound_tx }, iface },
    );

    // Inbound: decrypted data from the router → the stream's read side.
    tokio::spawn(async move {
        while let Some(bytes) = inbound_rx.recv().await {
            if write_half.write_all(&bytes).await.is_err() {
                break;
            }
        }
        // The inbound channel closed: the link was torn down (a peer link-close, or
        // the endpoint shutting down). Shut the write side explicitly so the reader
        // sees EOF — dropping this half alone would not, since the outbound relay
        // still holds the duplex's read half alive.
        let _ = write_half.shutdown().await;
    });

    // Outbound: the stream's writes → encrypted link data packets, out the link's interface.
    let out_link = link;
    let iv_shared = Arc::clone(shared);
    tokio::spawn(async move {
        let mut buf = [0u8; WRITE_CHUNK];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    // The stream was shut down or dropped: close the link so the
                    // peer's read side sees EOF. This is what lets a read-to-end
                    // protocol (e.g. gemini) end a response by closing the stream.
                    iv_shared.send_on(iface, out_link.close_packet());
                    break;
                }
                Ok(n) => {
                    let iv = next_iv();
                    iv_shared.send_on(iface, out_link.data_packet(&buf[..n], &iv));
                }
            }
        }
    });

    LinkStream { inner: mine, link_id }
}

/// Build a **reliable** [`LinkStream`] for a live link: the RNS Channel/Buffer path with
/// link-proof acks (see [`crate::reliable`]). A single driver task owns the
/// [`ReliableChannel`] and pumps it — app writes in, ordered bytes out, a proof per
/// delivered packet, an inbound proof releasing its sequence, and retransmits on a clock —
/// so the stream stays honest over a lossy interface. `peer` is the identity whose proofs
/// this side validates (the destination's identity, for an initiator).
fn register_reliable_stream(shared: &Arc<Shared>, link: Link, iface: InterfaceId, peer: Identity) -> LinkStream {
    let (mine, theirs) = tokio::io::duplex(DUPLEX_BUF);
    let (mut read_half, mut write_half) = tokio::io::split(theirs);
    let (pkt_tx, mut pkt_rx) = mpsc::unbounded_channel::<Packet>();
    let link_id = link.id();

    shared.links.lock().unwrap().insert(
        link_id,
        LinkEntry { link: link.clone(), kind: LinkKind::Reliable { packets: pkt_tx }, iface },
    );

    let close_link = link.clone();
    let mut rc = ReliableChannel::new(link, shared.identity.clone(), peer);
    let drv = Arc::clone(shared);
    tokio::spawn(async move {
        let mut buf = [0u8; WRITE_CHUNK];
        let mut clock: u64 = 0;
        let mut writer_open = true; // the app's write side is still open
        let mut peer_done = false; // the peer signalled end-of-stream (its eof frame)
        let mut interval = tokio::time::interval(Duration::from_millis(RELIABLE_TICK_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Raw inbound packets from the router: channel data (prove + deliver), an
                // ack (release its sequence), or the peer's link close.
                maybe = pkt_rx.recv() => {
                    let Some(pkt) = maybe else { break }; // router dropped the link
                    if pkt.packet_type == PacketType::Proof {
                        rc.on_proof(&pkt, clock);
                    } else if pkt.context == CTX_CHANNEL {
                        if let Some(proof) = rc.on_data_packet(&pkt) {
                            drv.send_on(iface, proof);
                        }
                        let bytes = rc.read();
                        if !bytes.is_empty() && write_half.write_all(&bytes).await.is_err() {
                            break;
                        }
                        if rc.recv_finished() {
                            // The peer's stream ended: close our read side so the app's
                            // reader sees EOF. We keep running to finish our own sending.
                            let _ = write_half.shutdown().await;
                            peer_done = true;
                        }
                    } else if pkt.context == CTX_LINKCLOSE {
                        let _ = write_half.shutdown().await;
                        break;
                    }
                }
                // App writes -> the reliable send queue. Disabled once the writer closes, so
                // we do not spin on end-of-stream.
                res = read_half.read(&mut buf), if writer_open => {
                    match res {
                        Ok(0) | Err(_) => {
                            rc.finish(); // queue the eof frame
                            writer_open = false;
                        }
                        Ok(n) => rc.write(&buf[..n]),
                    }
                }
                // The retransmit clock.
                _ = interval.tick() => {
                    clock += 1;
                }
            }

            // After any event, put ready channel packets on the wire: new data within the
            // window, plus retransmits past their timeout.
            for pkt in rc.poll_transmit(clock, next_iv) {
                drv.send_on(iface, pkt);
            }

            // The stream is fully done only when our side finished sending (write closed and
            // everything, including our eof frame, sent and proven) AND the peer finished
            // sending (its eof arrived). This preserves half-close: after our write closes we
            // keep delivering the peer's reply until it, too, ends. Then close the link.
            if !writer_open && peer_done && rc.send_idle() {
                drv.send_on(iface, close_link.close_packet());
                break;
            }
        }
        drv.links.lock().unwrap().remove(&link_id);
    });

    LinkStream { inner: mine, link_id }
}

/// Removes a link's pending-setup state — the `pending` waker and the `pending_links`
/// half-open link — if setup does not complete: a timeout, or the caller dropping the `open`
/// future. Without it, a setup that never receives its proof leaks both entries. Disarmed
/// once the proof establishes the link, since the router has already removed them.
struct PendingGuard {
    shared: Arc<Shared>,
    link_id: AddressHash,
    armed: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if self.armed {
            self.shared.pending.lock().unwrap().remove(&self.link_id);
            self.shared.pending_links.lock().unwrap().remove(&self.link_id);
        }
    }
}

/// Fill `buf` with cryptographically secure OS randomness. Link ephemeral secrets and AES
/// IVs depend on this being unpredictable — the whole link's secrecy rests on the ephemeral
/// key an eavesdropper must not be able to guess — so a failure to obtain entropy is fatal:
/// this panics rather than hand back weak bytes.
fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("OS CSPRNG unavailable");
}

/// A fresh 10-byte announce randomness value.
fn rand_hash() -> [u8; RAND_HASH_LEN] {
    let mut out = [0u8; RAND_HASH_LEN];
    fill_random(&mut out);
    out
}

/// A fresh 64-byte link ephemeral seed (`x25519_secret(32) || ed25519_seed(32)`), unique and
/// unpredictable per link.
fn ephemeral_seed() -> [u8; 64] {
    let mut seed = [0u8; 64];
    fill_random(&mut seed);
    seed
}

/// A fresh AES-CBC IV. Must be unpredictable per packet under a given link key.
fn next_iv() -> [u8; IV_LEN] {
    let mut iv = [0u8; IV_LEN];
    fill_random(&mut iv);
    iv
}
