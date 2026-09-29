use std::sync::{Arc, RwLock};

use crate::crypto::vote::VoteRecord;
use crate::net::gossip::GossipMessage;
use crate::net::phonebook::Phonebook;
use crate::storage::db::Database;

/// Handles incoming P2P Domain Reputation Vote broadcast packets (PAYLOAD_TYPE_VOTE = 2)
///
/// Enforces:
/// 1. Headless nodes cannot cast consensus votes.
/// 2. Strict sequence monotonicity: if previous monotonic vote is not present, drop/reject.
/// 3. Logarithmic difficulty and causal challenge binding (REP-01 & REP-02).
pub fn handle_vote_packet(
    msg: &GossipMessage,
    db: &Arc<Database>,
    phonebook: &Arc<RwLock<Phonebook>>,
) {
    let vote: VoteRecord = match serde_json::from_slice(&msg.payload) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("  ⚠️ [P2P Vote] Failed to deserialize vote record: {}", err);
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    // 1. Originator consistency check
    if vote.voter_pubkey != msg.originator_pubkey {
        eprintln!(
            "  ⚠️ [P2P Vote] Originator pubkey mismatch: gossip msg {:02x?} != vote record {:02x?}",
            &msg.originator_pubkey[..4],
            &vote.voter_pubkey[..4]
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 2. Headless node constraint: headless nodes cannot vote since navigation is disabled
    let is_headless = phonebook
        .read()
        .map(|pb| pb.is_peer_headless(&vote.voter_pubkey))
        .unwrap_or(false);
    if is_headless {
        eprintln!(
            "  ⚠️ [P2P Vote] Rejected vote from headless peer {:02x?}: infrastructure nodes cannot vote",
            &vote.voter_pubkey[..4]
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 3. Monotonic sequence check: if previous monotonic vote is not here yet, reject immediately
    let (prev_vote, active_votes, revisions_on_domain) =
        db.get_vote_context(&vote.voter_pubkey, &vote.domain);

    let expected_seq = prev_vote.as_ref().map(|p| p.vote_seq + 1).unwrap_or(1);
    if vote.vote_seq != expected_seq {
        eprintln!(
            "  ⚠️ [P2P Vote] Rejected vote for `{}`: sequence discontinuity (expected seq {}, found {})",
            vote.domain, expected_seq, vote.vote_seq
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 4. Validate cryptographic signature, challenge binding, and PoW difficulty
    if let Err(err) =
        vote.validate_against_chain(prev_vote.as_ref(), active_votes, revisions_on_domain)
    {
        eprintln!(
            "  ⚠️ [P2P Vote] Solipsistic vote rejected for `{}`: {}",
            vote.domain, err
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 5. Ingest valid vote into database and record event log
    let _ = db.record_gossip_event(msg, false);

    if let Err(err) = db.insert_vote(vote.clone()) {
        eprintln!(
            "  ⚠️ [P2P Vote] Failed to persist vote for `{}`: {}",
            vote.domain, err
        );
        return;
    }

    println!(
        "  🗳️ [P2P Vote] Ingested verified Vote #{} ({}) for `{}` from {:02x?}",
        vote.vote_seq,
        vote.action,
        vote.domain,
        &vote.voter_pubkey[..4]
    );
}
