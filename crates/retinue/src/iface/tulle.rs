//! Bridge between an endpoint raw interface and a Tulle packet radio.

use std::io;

use tulle::radio_io::PacketRadio;

use crate::endpoint::Interface;
use crate::packet::Packet;

/// Drive one endpoint interface over a running Tulle radio until either side
/// closes or an outbound packet cannot be transmitted.
///
/// Malformed RF packets are dropped at the boundary. An outbound packet larger
/// than the selected radio personality's frame limit is reported explicitly.
/// Retinue still advertises its ordinary 500-byte protocol MTU, so callers
/// should treat links with a smaller physical cap as experimental until
/// interface-specific MTU negotiation lands.
pub async fn drive<R>(interface: Interface, mut radio: R) -> io::Result<()>
where
    R: PacketRadio,
{
    let max_frame_len = radio.max_frame_len();
    let (mut outbound, sink) = interface.split();

    loop {
        tokio::select! {
            packet = outbound.recv() => {
                let Some(packet) = packet else {
                    return Ok(());
                };
                let bytes = packet.encode();
                if bytes.len() > max_frame_len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "retinue packet is {} bytes, radio frame limit is {max_frame_len}",
                            bytes.len()
                        ),
                    ));
                }
                radio
                    .send_frame(bytes)
                    .await
                    .map_err(|error| io::Error::other(error.to_string()))?;
            }
            received = radio.recv_frame() => {
                let Some(received) = received else {
                    return Ok(());
                };
                let Ok(packet) = Packet::decode(&received.frame) else {
                    continue;
                };
                if !sink.deliver(packet) {
                    return Ok(());
                }
            }
        }
    }
}
