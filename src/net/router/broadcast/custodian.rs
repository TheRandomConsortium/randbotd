use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::UdpSocket;

use crate::crypto::identity::NodeIdentity;
use crate::net::gossip::{
    GossipMessage, DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_CA_CAPABILITIES_PROOF,
    PAYLOAD_TYPE_CUSTODIAN_DELEGATION_REQ, PAYLOAD_TYPE_SWARM_ACTIVATION,
};
use crate::net::router::tcp::CertificateTcpClient;
use crate::net::router::GossipRouter;
use crate::pki::ca::compute_ca_id;
use crate::pki::swarm::{
    CACapabilitiesProof, CustodianContract, CustodianDelegationRequest, CustodianSwarmRecord,
    SwarmActivationConfirmation,
};
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

/// Handles incoming CustodianContract packets (PAYLOAD_TYPE_CUSTODIAN_CONTRACT = 17)
pub async fn handle_custodian_contract_packet(
    msg: &GossipMessage,
    db: &Arc<Database>,
    identity: Option<&NodeIdentity>,
    socket: &UdpSocket,
    router: &GossipRouter,
) {
    let contract: CustodianContract = match serde_json::from_slice(&msg.payload) {
        Ok(c) => c,
        Err(_) => {
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    if contract.verify_signature().is_err() {
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if contract.is_expired(now) {
        return;
    }

    let ca = match db.get_ca(&contract.ca_id) {
        Some(c) => c,
        None => return,
    };

    if ca.is_draft || !ca.seeking_custodians {
        return;
    }

    let my_identity = match identity {
        Some(id) => id,
        None => return,
    };

    let my_pubkey = my_identity.verifying_key().to_bytes();
    let expected_ca_id = compute_ca_id(&ca.subject.common_name, &my_pubkey);
    if ca.ca_id != expected_ca_id {
        return;
    }

    // Local blind policy evaluation
    let policy = db.get_ca_custodian_policy(&ca.ca_id).unwrap_or_default();

    if contract.work_share_pct > policy.max_work_share_pct {
        eprintln!(
            "  🤫 [Custodian Contract] Silently dropped petition: work-share {}% exceeds policy ceiling {}%",
            contract.work_share_pct, policy.max_work_share_pct
        );
        return;
    }

    let active_custodians = db.get_custodians_for_ca(&ca.ca_id);
    if active_custodians.len() >= policy.target_swarm_size {
        eprintln!(
            "  🤫 [Custodian Contract] Silently dropped petition: active swarm size {} reaches target {}",
            active_custodians.len(),
            policy.target_swarm_size
        );
        return;
    }

    let commitment_window = contract.valid_until.saturating_sub(contract.created_at);
    if commitment_window < policy.min_ttl_seconds {
        eprintln!(
            "  🤫 [Custodian Contract] Silently dropped petition: commitment window {}s is under policy min {}s",
            commitment_window, policy.min_ttl_seconds
        );
        return;
    }

    let contract_hash = contract.contract_hash();
    router
        .pending_contracts
        .write()
        .unwrap()
        .insert(contract_hash, contract.clone());

    if !policy.auto_accept {
        println!(
            "  📥 [Custodian Contract] Staged petition from {:02x?} for manual review (CA ID: {})",
            &contract.worker_pubkey[..4],
            bytes32_to_hex(&ca.ca_id)
        );
        return;
    }

    // Step 2: Auto-issue CustodianDelegationRequest challenge
    let offers = db.list_offers_for_ca(&ca.ca_id);
    let target_offer_id = offers.first().map(|o| o.offer_id).unwrap_or(1);
    let challenge_nonce = rand::random::<u64>();

    let delegation_req = CustodianDelegationRequest::new(
        ca.ca_id,
        contract.worker_pubkey,
        contract_hash,
        challenge_nonce,
        target_offer_id,
        my_identity.signing_key(),
    );

    if let Ok(payload) = serde_json::to_vec(&delegation_req) {
        let gossip_msg = GossipMessage::new(
            my_identity.signing_key(),
            msg.seq.wrapping_add(1),
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_CUSTODIAN_DELEGATION_REQ,
            payload,
        );
        router.broadcast(&gossip_msg, socket).await;
        println!(
            "  🤝 [Custodian Delegation] Emitted challenge for worker {:02x?} under CA `{}`",
            &contract.worker_pubkey[..4],
            ca.subject.common_name
        );
    }
}

/// Handles incoming CustodianDelegationRequest packets (PAYLOAD_TYPE_CUSTODIAN_DELEGATION_REQ = 18)
pub async fn handle_custodian_delegation_req_packet(
    msg: &GossipMessage,
    db: &Arc<Database>,
    identity: Option<&NodeIdentity>,
    socket: &UdpSocket,
    router: &GossipRouter,
) {
    let req: CustodianDelegationRequest = match serde_json::from_slice(&msg.payload) {
        Ok(r) => r,
        Err(_) => return,
    };

    let my_identity = match identity {
        Some(id) => id,
        None => return,
    };

    if req.worker_pubkey != my_identity.verifying_key().to_bytes() {
        return;
    }

    if req.verify_signature(&msg.originator_pubkey).is_err() {
        return;
    }

    let offers = db.list_offers_for_ca(&req.ca_id);
    let target_offer = match offers
        .into_iter()
        .find(|o| o.offer_id == req.target_offer_id)
    {
        Some(o) => o,
        None => return,
    };

    // Build mock certificate artifact adhering to catalog offer algorithm
    let sample_cert = format!(
        "-----BEGIN CERTIFICATE-----\nRANDBOTD_MOCK_CAPABILITY_CERTIFICATE_{:?}_{}\n-----END CERTIFICATE-----\n",
        target_offer.key_algorithm, req.challenge_nonce
    )
    .into_bytes();

    let cert_len = sample_cert.len() as u32;
    let mut hasher = Sha256::new();
    hasher.update(&sample_cert);
    let mock_cert_hash: [u8; 32] = hasher.finalize().into();

    router
        .mock_cert_store
        .write()
        .unwrap()
        .insert(mock_cert_hash, sample_cert);

    // Step 3: Emit CACapabilitiesProof
    let proof = CACapabilitiesProof::new(
        req.ca_id,
        my_identity.signing_key(),
        req.contract_hash,
        mock_cert_hash,
        target_offer.key_algorithm,
        cert_len,
    );

    if let Ok(payload) = serde_json::to_vec(&proof) {
        let gossip_msg = GossipMessage::new(
            my_identity.signing_key(),
            msg.seq.wrapping_add(1),
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_CA_CAPABILITIES_PROOF,
            payload,
        );
        router.broadcast(&gossip_msg, socket).await;
        println!(
            "  📜 [Custodian Proof] Emitted CACapabilitiesProof for CA ID {:02x?} (Algorithm: {:?})",
            &req.ca_id[..4],
            target_offer.key_algorithm
        );
    }
}

/// Handles incoming CACapabilitiesProof packets (PAYLOAD_TYPE_CA_CAPABILITIES_PROOF = 19)
pub async fn handle_ca_capabilities_proof_packet(
    msg: &GossipMessage,
    db: &Arc<Database>,
    identity: Option<&NodeIdentity>,
    socket: &UdpSocket,
    router: &GossipRouter,
) {
    let proof: CACapabilitiesProof = match serde_json::from_slice(&msg.payload) {
        Ok(p) => p,
        Err(_) => return,
    };

    if proof.verify_signature().is_err() {
        return;
    }

    let my_identity = match identity {
        Some(id) => id,
        None => return,
    };

    let ca = match db.get_ca(&proof.ca_id) {
        Some(c) => c,
        None => return,
    };

    let my_pubkey = my_identity.verifying_key().to_bytes();
    let expected_ca_id = compute_ca_id(&ca.subject.common_name, &my_pubkey);
    if ca.ca_id != expected_ca_id {
        return;
    }

    let contract = {
        let pending = router.pending_contracts.read().unwrap();
        match pending.get(&proof.contract_hash).cloned() {
            Some(c) => c,
            None => return,
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if contract.is_expired(now) {
        eprintln!(
            "  ⚠️ [Swarm Activation] Contract expired for worker {:02x?}. Silently dropping.",
            &proof.worker_pubkey[..4]
        );
        return;
    }

    // Step 4a: Retrieve mock certificate over TCP via hardened client
    println!(
        "  🌐 [TCP Cert Fetch] Connecting to worker `{}` to fetch mock cert {:02x?}...",
        contract.tcp_endpoint,
        &proof.mock_cert_hash[..4]
    );

    let cert_bytes = match CertificateTcpClient::fetch_mock_cert(
        &contract.tcp_endpoint,
        &proof.mock_cert_hash,
    )
    .await
    {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "  ⚠️ [Swarm Activation] TCP cert fetch failed for candidate {:02x?}: {}. Silently dropping.",
                &proof.worker_pubkey[..4],
                err
            );
            return;
        }
    };

    if cert_bytes.is_empty() {
        return;
    }

    // Step 4b: Emit SwarmActivationConfirmation
    let confirmation = SwarmActivationConfirmation::new(
        ca.ca_id,
        proof.worker_pubkey,
        proof.contract_hash,
        proof.mock_cert_hash,
        now,
        my_identity.signing_key(),
    );

    if confirmation
        .verify_against_contract(&contract, &my_pubkey)
        .is_err()
    {
        return;
    }

    let record = CustodianSwarmRecord {
        ca_id: ca.ca_id,
        worker_pubkey: proof.worker_pubkey,
        work_share_pct: contract.work_share_pct,
        tcp_endpoint: contract.tcp_endpoint.clone(),
        activated_at: now,
        contract_hash: proof.contract_hash,
        mock_cert_hash: proof.mock_cert_hash,
    };

    let _ = db.insert_custodian_record(record);

    if let Ok(payload) = serde_json::to_vec(&confirmation) {
        let gossip_msg = GossipMessage::new(
            my_identity.signing_key(),
            msg.seq.wrapping_add(1),
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_SWARM_ACTIVATION,
            payload,
        );
        router.broadcast(&gossip_msg, socket).await;
        println!(
            "  🌟 [Swarm Activation] Admitted custodian {:02x?} to CA `{}` swarm after TCP verification!",
            &proof.worker_pubkey[..4],
            ca.subject.common_name
        );
    }
}

/// Handles incoming SwarmActivationConfirmation packets (PAYLOAD_TYPE_SWARM_ACTIVATION = 20)
pub fn handle_swarm_activation_packet(msg: &GossipMessage, db: &Arc<Database>) {
    let conf: SwarmActivationConfirmation = match serde_json::from_slice(&msg.payload) {
        Ok(c) => c,
        Err(_) => {
            let _ = db.record_gossip_event(msg, true);
            return;
        }
    };

    let ca = match db.get_ca(&conf.ca_id) {
        Some(c) => c,
        None => return,
    };

    if conf.verify_signature(&msg.originator_pubkey).is_err() {
        let _ = db.record_gossip_event(msg, true);
        return;
    }

    let _ = db.record_gossip_event(msg, false);

    let record = CustodianSwarmRecord {
        ca_id: conf.ca_id,
        worker_pubkey: conf.worker_pubkey,
        work_share_pct: 0,
        tcp_endpoint: String::new(),
        activated_at: conf.activated_at,
        contract_hash: conf.contract_hash,
        mock_cert_hash: conf.mock_cert_hash,
    };

    if let Err(e) = db.insert_custodian_record(record) {
        eprintln!("  ⚠️ [P2P Swarm] Failed to persist custodian record: {}", e);
        return;
    }

    println!(
        "  🛡️ [P2P Swarm] Ingested verified custodian {:02x?} for CA `{}`",
        &conf.worker_pubkey[..4],
        ca.subject.common_name
    );
}
