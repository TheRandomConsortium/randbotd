use std::sync::Arc;

use crate::net::gossip::GossipMessage;
use crate::pki::ca::{compute_ca_id, CaDeclaration};
use crate::pki::chain::CertificateChain;
use crate::pki::crl::CertificateRevocationList;
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

/// Handles incoming P2P CA Declaration broadcast packets (PAYLOAD_TYPE_CA_DECLARATION = 3)
pub fn handle_ca_declaration_packet(msg: &GossipMessage, db: &Arc<Database>) {
    let decl: CaDeclaration = match serde_json::from_slice(&msg.payload) {
        Ok(d) => d,
        Err(err) => {
            eprintln!(
                "  ⚠️ [P2P CA Broadcast] Failed to deserialize CA declaration from peer: {}",
                err
            );
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    // User directive: only non-draft declarations are accepted from the swarm
    if decl.is_draft {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Ignored draft CA declaration `{}` from peer",
            decl.subject.common_name
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    if let Err(err) = decl.subject.validate() {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Invalid CA subject metadata: {}",
            err
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }
    if let Err(err) = decl.issuer.validate() {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Invalid CA issuer metadata: {}",
            err
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // Verify deterministic CA ID binding against originator public key
    let expected_ca_id = compute_ca_id(&decl.subject.common_name, &msg.originator_pubkey);
    if decl.ca_id != expected_ca_id {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Mismatched ca_id: expected `{}`, got `{}`",
            bytes32_to_hex(&expected_ca_id),
            bytes32_to_hex(&decl.ca_id)
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // Ingest valid CA declaration into immutable event log
    let _ = db.record_gossip_event(msg, false);

    if let Err(err) = db.insert_ca(decl.clone()) {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Failed to save CA declaration: {}",
            err
        );
        return;
    }

    println!(
        "  📜 [P2P CA Broadcast] Ingested verified CA Declaration `{}` (CA ID: {})",
        decl.subject.common_name,
        bytes32_to_hex(&decl.ca_id)
    );
}

/// Handles incoming P2P Certificate Chain broadcast packets (PAYLOAD_TYPE_CERT_CHAIN = 4)
pub fn handle_cert_chain_packet(msg: &GossipMessage, db: &Arc<Database>) {
    let chain: CertificateChain = match serde_json::from_slice(&msg.payload) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  ⚠️ [P2P Chain Broadcast] Deserialization error: {}", e);
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let known_cas = db.list_cas();
    if let Err(err) = chain.validate(&known_cas, now) {
        eprintln!(
            "  ⚠️ [P2P Chain Broadcast] Rejected invalid cert chain for `{}`: {}",
            chain.target_certificate.subject.common_name, err
        );
        return;
    }

    let chain_id = match db.insert_cert_chain(chain.clone()) {
        Ok(id) => id,
        Err(err) => {
            eprintln!(
                "  ⚠️ [P2P Chain Broadcast] Failed to persist cert chain: {}",
                err
            );
            return;
        }
    };

    println!(
        "  🔗 [P2P Chain Broadcast] Ingested verified CertificateChain for `{}` (Chain ID: {}, Depth: {})",
        chain.target_certificate.subject.common_name,
        bytes32_to_hex(&chain_id),
        chain.ordered_certificates().len()
    );
}

/// Handles incoming P2P CRL broadcast packets (PAYLOAD_TYPE_CRL_BROADCAST = 14)
pub fn handle_crl_broadcast_packet(msg: &GossipMessage, db: &Arc<Database>) {
    let crl: CertificateRevocationList = match serde_json::from_slice(&msg.payload) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  ⚠️ [P2P CRL Broadcast] Deserialization error: {}", e);
            return;
        }
    };

    // If issuing CA is known, verify CRL signature against issuing CA public key
    if let Some(ca) = db.get_ca(&crl.issuer_ca_id) {
        // Derive expected public key if available or check originator
        let pubkey_bytes = msg.originator_pubkey;
        if let Err(err) = crl.verify_signature(&pubkey_bytes) {
            eprintln!(
                "  ⚠️ [P2P CRL Broadcast] Invalid CRL signature for CA `{}`: {}",
                ca.subject.common_name, err
            );
            return;
        }
    }

    let ca_id = match db.insert_crl(crl.clone()) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("  ⚠️ [P2P CRL Broadcast] Failed to store CRL: {}", err);
            return;
        }
    };

    println!(
        "  🚫 [P2P CRL Broadcast] Ingested verified CRL #{} for CA `{}` (Revoked: {})",
        crl.crl_number,
        bytes32_to_hex(&ca_id),
        crl.revoked_certificates.len()
    );
}

/// Handles incoming P2P Domain Purge broadcast packets (PAYLOAD_TYPE_DOMAIN_PURGE = 15)
pub fn handle_domain_purge_packet(msg: &GossipMessage, db: &Arc<Database>) {
    let purge: crate::pki::purge::DomainPurgeRecord = match serde_json::from_slice(&msg.payload) {
        Ok(p) => p,
        Err(err) => {
            eprintln!(
                "  ⚠️ [P2P Domain Purge] Failed to deserialize domain purge record: {}",
                err
            );
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    // 1. Verify target CA exists and is non-draft
    let ca = match db.get_ca(&purge.ca_id) {
        Some(c) => c,
        None => {
            eprintln!(
                "  ⚠️ [P2P Domain Purge] Rejected purge for unknown CA ID {:02x?}",
                &purge.ca_id[..4]
            );
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    if ca.is_draft {
        eprintln!(
            "  ⚠️ [P2P Domain Purge] Rejected purge under draft CA `{}`",
            ca.subject.common_name
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 2. Query previous purge state for this CA to validate chain continuity and PoW
    let ca_purges = db.get_purges_for_ca(&purge.ca_id);
    let prev_purge = ca_purges.last();
    let active_unexpired_count =
        db.count_active_unexpired_purges_for_ca(&purge.ca_id, purge.timestamp);

    // 3. Cryptographic and chain validation (anti-solipsism defense)
    if let Err(err) = purge.validate_against_ca_and_chain(
        &ca,
        &msg.originator_pubkey,
        prev_purge,
        active_unexpired_count,
    ) {
        eprintln!(
            "  ⚠️ [P2P Domain Purge] Solipsistic purge rejected for `{}`: {}",
            purge.domain, err
        );
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    // 4. Ingest valid purge into database subtable and event log
    let _ = db.record_gossip_event(msg, false);

    if let Err(err) = db.insert_purge(purge.clone()) {
        eprintln!(
            "  ⚠️ [P2P Domain Purge] Failed to persist purge for `{}`: {}",
            purge.domain, err
        );
        return;
    }

    println!(
        "  🧹 [P2P Domain Purge] Ingested verified Bad-Domain Purge #{} for `{}` under CA `{}`",
        purge.purge_seq, purge.domain, ca.subject.common_name
    );
}

/// Automated broadcast of published non-draft CAs, certificate chains, and CRLs across the P2P swarm (CA-04)
pub async fn broadcast_published_pki_entities(
    router: &crate::net::router::GossipRouter,
    db: &Database,
    identity: &crate::crypto::identity::NodeIdentity,
    socket: &tokio::net::UdpSocket,
) {
    let published_cas = db.list_cas();
    for ca in &published_cas {
        if !ca.is_draft {
            if let Ok(ca_payload) = serde_json::to_vec(ca) {
                let gossip_ca = GossipMessage::new(
                    identity.signing_key(),
                    3,
                    crate::net::gossip::DEFAULT_GOSSIP_TTL,
                    crate::net::gossip::PAYLOAD_TYPE_CA_DECLARATION,
                    ca_payload,
                );
                router.broadcast(&gossip_ca, socket).await;
                println!(
                    "  -> Broadcasted Signed Root CA Declaration `{}` (ID: {:02x?})",
                    ca.subject.common_name,
                    &gossip_ca.msg_id[..4]
                );
            }
        }
    }

    for chain in db.list_cert_chains() {
        if let Ok(chain_payload) = serde_json::to_vec(&chain) {
            let gossip_chain = GossipMessage::new(
                identity.signing_key(),
                4,
                crate::net::gossip::DEFAULT_GOSSIP_TTL,
                crate::net::gossip::PAYLOAD_TYPE_CERT_CHAIN,
                chain_payload,
            );
            router.broadcast(&gossip_chain, socket).await;
            println!(
                "  -> Broadcasted CertificateChain for `{}` (ID: {:02x?})",
                chain.target_certificate.subject.common_name,
                &gossip_chain.msg_id[..4]
            );
        }
    }

    for crl in db.list_crls() {
        if let Ok(crl_payload) = serde_json::to_vec(&crl) {
            let gossip_crl = GossipMessage::new(
                identity.signing_key(),
                5,
                crate::net::gossip::DEFAULT_GOSSIP_TTL,
                crate::net::gossip::PAYLOAD_TYPE_CRL_BROADCAST,
                crl_payload,
            );
            router.broadcast(&gossip_crl, socket).await;
            println!(
                "  -> Broadcasted CRL #{} for CA ID {:02x?} (ID: {:02x?})",
                crl.crl_number,
                &crl.issuer_ca_id[..4],
                &gossip_crl.msg_id[..4]
            );
        }
    }

    for purge in db.list_purges() {
        if let Ok(purge_payload) = serde_json::to_vec(&purge) {
            let gossip_purge = GossipMessage::new(
                identity.signing_key(),
                6,
                crate::net::gossip::DEFAULT_GOSSIP_TTL,
                crate::net::gossip::PAYLOAD_TYPE_DOMAIN_PURGE,
                purge_payload,
            );
            router.broadcast(&gossip_purge, socket).await;
            println!(
                "  -> Broadcasted Bad-Domain Purge #{} for `{}` (ID: {:02x?})",
                purge.purge_seq,
                purge.domain,
                &gossip_purge.msg_id[..4]
            );
        }
    }
}

#[cfg(test)]
mod tests;
