use super::GossipRouter;
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
    router: &GossipRouter,
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

        // Track continuous ranges for peer saturation suppression
        for orig_vec in &req.vector {
            if orig_vec.known_ranges.len() == 1 {
                let r = &orig_vec.known_ranges[0];
                if r.start == 1 {
                    router.mark_originator_saturated(src, orig_vec.originator, r.end);
                }
            }
        }

        let mut missing_for_peer = db.find_missing_entries_for_peer(&req.vector, 20);
        let my_vector = db.get_originator_range_vectors(8);

        // Enforce 1024-byte UDP MTU payload budget
        while missing_for_peer.len() > 1 {
            let test_payload = RangeSyncResponse {
                entries_for_peer: missing_for_peer.clone(),
                my_vector: my_vector.clone(),
            };
            if let Ok(bytes) = serde_json::to_vec(&test_payload) {
                if bytes.len() <= 1024 {
                    break;
                }
            }
            missing_for_peer.pop();
        }

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
    _router: &GossipRouter,
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
            let mut missing_for_peer = db.find_missing_entries_for_peer(&resp.my_vector, 20);
            if !missing_for_peer.is_empty() {
                while missing_for_peer.len() > 1 {
                    let test_payload = RangeSyncResponse {
                        entries_for_peer: missing_for_peer.clone(),
                        my_vector: Vec::new(),
                    };
                    if let Ok(bytes) = serde_json::to_vec(&test_payload) {
                        if bytes.len() <= 1024 {
                            break;
                        }
                    }
                    missing_for_peer.pop();
                }

                let resp_payload = RangeSyncResponse {
                    entries_for_peer: missing_for_peer,
                    my_vector: Vec::new(),
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
    router: &GossipRouter,
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(req) = serde_json::from_slice::<MerkleDrillRequest>(&msg.payload) {
        // Anti-Spam Saturation Check: If peer sent continuous range covering target_range.end, suppress drill
        if router.is_originator_saturated(src, &req.originator, req.target_range.end) {
            println!(
                "  🚫 [Anti-Entropy Anti-Spam] Suppressed redundant MerkleDrillRequest from saturated peer {}",
                src
            );
            return;
        }

        println!(
            "  🌳 [Anti-Entropy Merkle] Received MerkleDrillRequest for node {:02x?} range [{}..{}] (Nonce: {}) from {}",
            &req.originator[..4],
            req.target_range.start,
            req.target_range.end,
            req.nonce,
            src
        );
        let (left_child, right_child) = db.get_merkle_children(&req.originator, &req.target_range);
        let resp_payload = MerkleDrillResponse {
            nonce: req.nonce,
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
    router: &GossipRouter,
    msg: &GossipMessage,
    src: SocketAddr,
    socket: &UdpSocket,
    identity: Option<&NodeIdentity>,
    db: &Database,
) {
    if let Ok(resp) = serde_json::from_slice::<MerkleDrillResponse>(&msg.payload) {
        // Anti-Spam Nonce Validation
        if !router.validate_and_take_nonce(resp.nonce) {
            println!(
                "  🚫 [Anti-Spam] Unsolicited or invalid MerkleDrillResponse (Nonce: {}) from peer {}. Banning peer for 300s!",
                resp.nonce, src
            );
            router.ban_peer(src, 300);
            return;
        }

        println!(
            "  🌳 [Anti-Entropy Merkle] Received verified MerkleDrillResponse (Nonce: {}) for node {:02x?} from {}",
            resp.nonce,
            &resp.originator[..4],
            src
        );

        let children = vec![resp.left_child, resp.right_child];
        for child in children.into_iter().flatten() {
            let local_hash = db.compute_merkle_hash_for_range(&resp.originator, &child.range);
            if local_hash != Some(child.hash) {
                if child.range.start == child.range.end {
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
                    let drill_nonce = rand::random::<u64>();
                    router.register_drill_nonce(drill_nonce);

                    println!(
                        "  🔍 [Anti-Entropy Merkle] Drilling deeper into range [{}..{}] (Nonce: {}) for node {:02x?}",
                        child.range.start,
                        child.range.end,
                        drill_nonce,
                        &resp.originator[..4]
                    );
                    let drill_req = MerkleDrillRequest {
                        nonce: drill_nonce,
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
