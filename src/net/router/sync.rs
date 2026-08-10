use crate::crypto::identity::NodeIdentity;
use crate::net::gossip::{
    GossipMessage, RangeSyncRequest, RangeSyncResponse, PAYLOAD_TYPE_MERKLE_DRILL_RESP,
    PAYLOAD_TYPE_RANGE_SYNC_RESP,
};
use crate::net::history::{MerkleDrillRequest, MerkleDrillResponse};
use crate::storage::db::Database;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub async fn handle_range_sync_request(
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(req) = serde_json::from_slice::<RangeSyncRequest>(&msg.payload) {
        println!(
            "  🔄 [Anti-Entropy] Received RangeSyncRequest with {} range vectors from {}",
            req.vector.len(),
            src
        );
        let mut missing_for_peer = db.find_missing_entries_for_peer(&req.vector);
        missing_for_peer.truncate(16);
        let my_vector = db.get_originator_range_vectors(8);

        let resp_payload = RangeSyncResponse {
            entries_for_peer: missing_for_peer,
            my_vector,
        };

        if let Ok(resp_bytes) = serde_json::to_vec(&resp_payload) {
            if let Some(id) = identity {
                let resp_msg = GossipMessage::new(
                    id.signing_key(),
                    1,
                    1,
                    PAYLOAD_TYPE_RANGE_SYNC_RESP,
                    resp_bytes,
                );
                let _ = socket.send_to(&resp_msg.to_bytes(), src).await;
            }
        }
    }
}

pub async fn handle_range_sync_response(
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(resp) = serde_json::from_slice::<RangeSyncResponse>(&msg.payload) {
        println!(
            "  🔄 [Anti-Entropy] Received RangeSyncResponse with {} offered entries from {}",
            resp.entries_for_peer.len(),
            src
        );
        for entry in resp.entries_for_peer {
            if let Err(e) = db.append_event(entry) {
                eprintln!("  ⚠️ [Anti-Entropy] Ignored invalid sync entry: {}", e);
            }
        }

        // Symmetrical Step 3: Send back missing entries peer requested in my_vector
        if !resp.my_vector.is_empty() {
            let mut missing_for_peer = db.find_missing_entries_for_peer(&resp.my_vector);
            if !missing_for_peer.is_empty() {
                missing_for_peer.truncate(16);
                let resp_payload = RangeSyncResponse {
                    entries_for_peer: missing_for_peer,
                    my_vector: Vec::new(), // Symmetrical final step
                };
                if let Ok(resp_bytes) = serde_json::to_vec(&resp_payload) {
                    if let Some(id) = identity {
                        let resp_msg = GossipMessage::new(
                            id.signing_key(),
                            1,
                            1,
                            PAYLOAD_TYPE_RANGE_SYNC_RESP,
                            resp_bytes,
                        );
                        let _ = socket.send_to(&resp_msg.to_bytes(), src).await;
                    }
                }
            }
        }
    }
}

pub async fn handle_merkle_drill_request(
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(req) = serde_json::from_slice::<MerkleDrillRequest>(&msg.payload) {
        println!(
            "  🌳 [Anti-Entropy Merkle] Received MerkleDrillRequest for node {:02x?} range [{}..{}] from {}",
            &req.originator[..4],
            req.target_range.start,
            req.target_range.end,
            src
        );
        let (left_child, right_child) = db.get_merkle_children(&req.originator, &req.target_range);
        let resp_payload = MerkleDrillResponse {
            originator: req.originator,
            left_child,
            right_child,
        };
        if let Ok(resp_bytes) = serde_json::to_vec(&resp_payload) {
            if let Some(id) = identity {
                let resp_msg = GossipMessage::new(
                    id.signing_key(),
                    1,
                    1,
                    PAYLOAD_TYPE_MERKLE_DRILL_RESP,
                    resp_bytes,
                );
                let _ = socket.send_to(&resp_msg.to_bytes(), src).await;
            }
        }
    }
}

pub async fn handle_merkle_drill_response(
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(resp) = serde_json::from_slice::<MerkleDrillResponse>(&msg.payload) {
        println!(
            "  🌳 [Anti-Entropy Merkle] Received MerkleDrillResponse for node {:02x?} from {}",
            &resp.originator[..4],
            src
        );

        let children = vec![resp.left_child, resp.right_child];
        for child in children.into_iter().flatten() {
            let local_hash = db.compute_merkle_hash_for_range(&resp.originator, &child.range);
            if local_hash != Some(child.hash) {
                if child.range.start == child.range.end {
                    // Divergence isolated to a single sequence number! Request missing range entries
                    println!(
                        "  🎯 [Anti-Entropy Merkle] Isolated divergence to seq {} for node {:02x?}",
                        child.range.start,
                        &resp.originator[..4]
                    );
                    let sync_req = RangeSyncRequest {
                        vector: vec![crate::net::history::OriginatorRangeVector::new(
                            resp.originator,
                            vec![child.range],
                        )],
                    };
                    if let Ok(req_bytes) = serde_json::to_vec(&sync_req) {
                        if let Some(id) = identity {
                            let drill_msg = GossipMessage::new(
                                id.signing_key(),
                                1,
                                1,
                                crate::net::gossip::PAYLOAD_TYPE_RANGE_SYNC_REQ,
                                req_bytes,
                            );
                            let _ = socket.send_to(&drill_msg.to_bytes(), src).await;
                        }
                    }
                } else {
                    // Multi-event range divergence: Drill deeper into this subtree!
                    println!(
                        "  🔍 [Anti-Entropy Merkle] Drilling deeper into range [{}..{}] for node {:02x?}",
                        child.range.start,
                        child.range.end,
                        &resp.originator[..4]
                    );
                    let drill_req = MerkleDrillRequest {
                        originator: resp.originator,
                        target_range: child.range,
                    };
                    if let Ok(req_bytes) = serde_json::to_vec(&drill_req) {
                        if let Some(id) = identity {
                            let drill_msg = GossipMessage::new(
                                id.signing_key(),
                                1,
                                1,
                                crate::net::gossip::PAYLOAD_TYPE_MERKLE_DRILL_REQ,
                                req_bytes,
                            );
                            let _ = socket.send_to(&drill_msg.to_bytes(), src).await;
                        }
                    }
                }
            }
        }
    }
}
