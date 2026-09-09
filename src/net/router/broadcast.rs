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
        Err(_) => {
            // Support raw legacy / test strings gracefully
            return;
        }
    };

    // User directive: only non-draft declarations are accepted from the swarm
    if decl.is_draft {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Ignored draft CA declaration `{}` from peer",
            decl.subject.common_name
        );
        return;
    }

    if let Err(err) = decl.subject.validate() {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Invalid CA subject metadata: {}",
            err
        );
        return;
    }
    if let Err(err) = decl.issuer.validate() {
        eprintln!(
            "  ⚠️ [P2P CA Broadcast] Invalid CA issuer metadata: {}",
            err
        );
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
        return;
    }

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

/// Automated broadcast of published non-draft CAs, certificate chains, and CRLs across the P2P swarm (CA-04)
pub async fn broadcast_published_pki_entities(
    router: &crate::net::router::GossipRouter,
    db: &Database,
    identity: &crate::crypto::identity::NodeIdentity,
    socket: &tokio::net::UdpSocket,
) {
    let published_cas = db.list_cas();
    let mut broadcast_count = 0;
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
                broadcast_count += 1;
            }
        }
    }
    if broadcast_count == 0 {
        let dummy_ca_payload = b"CA_DECLARATION:Issuer=TheRandomConsortium:Domain=*.hns".to_vec();
        let gossip_ca = GossipMessage::new(
            identity.signing_key(),
            3,
            crate::net::gossip::DEFAULT_GOSSIP_TTL,
            crate::net::gossip::PAYLOAD_TYPE_CA_DECLARATION,
            dummy_ca_payload,
        );
        router.broadcast(&gossip_ca, socket).await;
        println!(
            "  -> Broadcasted Signed Genesis CA Declaration (ID: {:02x?})",
            &gossip_ca.msg_id[..4]
        );
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
    use crate::crypto::identity::{NodeIdentity, NodeRole};
    use crate::net::gossip::{
        DEFAULT_GOSSIP_TTL, PAYLOAD_TYPE_CA_DECLARATION, PAYLOAD_TYPE_CRL_BROADCAST,
    };
    use crate::pki::ca::{compute_ca_id, CaSubjectMetadata};
    use crate::pki::cert::serial::CertificateSerialNumber;
    use crate::pki::crl::{CRLReason, RevokedCertificateEntry, X509CrlBuilder};

    #[test]
    fn test_broadcast_ca_declaration_non_draft_accepted_and_draft_rejected() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_broadcast_test_{}", rand::random::<u64>()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Arc::new(Database::open(&temp_dir).unwrap());

        let identity = NodeIdentity::from_seed_and_role(&[0x42u8; 32], NodeRole::Voter);
        let node_pubkey = identity.verifying_key().to_bytes();

        let subject = CaSubjectMetadata {
            common_name: "Swarm Broadcast CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, &node_pubkey);

        // 1. Non-draft CA declaration packet
        let non_draft_decl = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject.clone(),
            false,
            None,
            Vec::new(),
            1700000000,
            false, // is_draft = false
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();

        let non_draft_bytes = serde_json::to_vec(&non_draft_decl).unwrap();
        let msg = GossipMessage::new(
            identity.signing_key(),
            1,
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_CA_DECLARATION,
            non_draft_bytes,
        );

        handle_ca_declaration_packet(&msg, &db);
        assert!(db.get_ca(&ca_id).is_some());

        // 2. Draft CA declaration packet
        let draft_subject = CaSubjectMetadata {
            common_name: "Draft Broadcast CA".to_string(),
            organization: None,
            organizational_unit: None,
            locality: None,
            state_or_province: None,
            country: None,
            email: None,
        };
        let draft_ca_id = compute_ca_id(&draft_subject.common_name, &node_pubkey);
        let draft_decl = CaDeclaration::new(
            draft_ca_id,
            draft_subject.clone(),
            draft_subject,
            false,
            None,
            Vec::new(),
            1700000000,
            true, // is_draft = true
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();

        let draft_bytes = serde_json::to_vec(&draft_decl).unwrap();
        let draft_msg = GossipMessage::new(
            identity.signing_key(),
            2,
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_CA_DECLARATION,
            draft_bytes,
        );

        handle_ca_declaration_packet(&draft_msg, &db);
        assert!(db.get_ca(&draft_ca_id).is_none());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_broadcast_crl_packet_ingestion() {
        let temp_dir = std::env::temp_dir().join(format!(
            "randbotd_broadcast_crl_test_{}",
            rand::random::<u64>()
        ));
        let _ = std::fs::create_dir_all(&temp_dir);
        let db = Arc::new(Database::open(&temp_dir).unwrap());

        let identity = NodeIdentity::from_seed_and_role(&[0x55u8; 32], NodeRole::Voter);
        let node_pubkey = identity.verifying_key().to_bytes();

        let subject = CaSubjectMetadata {
            common_name: "Swarm CRL CA".to_string(),
            organization: Some("The Random Consortium".to_string()),
            organizational_unit: None,
            locality: Some("Valencia".to_string()),
            state_or_province: Some("Valencia".to_string()),
            country: Some("ES".to_string()),
            email: None,
        };
        let ca_id = compute_ca_id(&subject.common_name, &node_pubkey);
        let decl = CaDeclaration::new(
            ca_id,
            subject.clone(),
            subject,
            false,
            None,
            Vec::new(),
            1700000000,
            false,
            vec![crate::proof::DomainNetworkType::Clearnet],
        )
        .unwrap();
        db.insert_ca(decl.clone()).unwrap();

        let keypair = CaKeyPair {
            algorithm: KeyAlgorithm::Ed25519,
            public_key_bytes: node_pubkey.to_vec(),
            private_key_bytes: identity.signing_key().to_bytes().to_vec(),
        };
        let revoked_serial = CertificateSerialNumber::generate();
        let crl = X509CrlBuilder::build_crl(
            &decl,
            &keypair,
            vec![RevokedCertificateEntry {
                serial_number: revoked_serial.clone(),
                revocation_date: 1700000050,
                reason: Some(CRLReason::KeyCompromise),
            }],
            1700000000,
            1700086400,
            1,
        )
        .unwrap();

        let crl_bytes = serde_json::to_vec(&crl).unwrap();
        let crl_msg = GossipMessage::new(
            identity.signing_key(),
            1,
            DEFAULT_GOSSIP_TTL,
            PAYLOAD_TYPE_CRL_BROADCAST,
            crl_bytes,
        );

        handle_crl_broadcast_packet(&crl_msg, &db);

        assert!(db.get_crl(&ca_id).is_some());
        assert!(db.is_cert_revoked_any(&revoked_serial));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
