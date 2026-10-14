//! A AddressBookPeers trait for getting the [`MetaAddr`] of recently live peers.

use chrono::Utc;

use crate::{meta_addr::MetaAddr, ConnectedPeer, PeerSocketAddr};

#[cfg(any(test, feature = "proptest-impl"))]
pub mod mock;

#[cfg(any(test, feature = "proptest-impl"))]
pub use mock::MockAddressBookPeers;

/// Method signatures for getting [`MetaAddr`]s of recently live peers.
pub trait AddressBookPeers {
    /// Return an Vec of peers we've seen recently, in reconnection attempt order.
    fn recently_live_peers(&self, now: chrono::DateTime<Utc>) -> Vec<MetaAddr>;

    /// Return active connection metadata when this implementation has a live-peer registry.
    fn connected_peers(&self) -> Option<Vec<ConnectedPeer>> {
        None
    }

    /// Count active legacy and native peers, falling back to recently live addresses
    /// only when this implementation does not provide a live connection registry.
    fn connected_peer_count(&self, now: chrono::DateTime<Utc>) -> usize {
        self.connected_peers()
            .map_or_else(|| self.recently_live_peers(now).len(), |peers| peers.len())
    }

    /// Add a peer to the address book.
    fn add_peer(&mut self, peer: PeerSocketAddr) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_peer_count_prefers_registry_including_empty_snapshot() {
        let mut peers = MockAddressBookPeers::default();
        peers.add_peer("127.0.0.1:19933".parse().expect("test address parses"));
        assert_eq!(peers.connected_peer_count(Utc::now()), 1);

        let peers = peers.with_connected_peers(Vec::new());
        assert_eq!(peers.connected_peer_count(Utc::now()), 0);

        let peers = peers.with_connected_peers(vec![
            ConnectedPeer::from_native(
                "127.0.0.1:19934".parse().expect("test address parses"),
                false,
            ),
            ConnectedPeer::from_native(
                "127.0.0.1:19935".parse().expect("test address parses"),
                true,
            ),
        ]);
        assert_eq!(peers.connected_peer_count(Utc::now()), 2);
    }
}
