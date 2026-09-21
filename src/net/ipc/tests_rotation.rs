use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::crypto::agility::KeyAlgorithm;
use crate::crypto::identity::{NodeIdentity, NodeRole};
use crate::net::ipc::{IpcCommand, IpcResponse, IpcServer};
use crate::net::phonebook::Phonebook;
use crate::pki::rotation::KeyRotationProof;
use crate::proof::DomainNetworkType;
use crate::storage::db::Database;

fn test_phonebook(pubkey: &[u8; 32]) -> Arc<RwLock<Phonebook>> {
    let mut pb = Phonebook::new();
    pb.set_my_pubkey(pubkey);
    Arc::new(RwLock::new(pb))
}

#[tokio::test]
async fn test_ipc_key_rotation_and_distrust_remediation_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_ipc_rotation_test_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let seed = [77u8; 32];
    let identity = Arc::new(NodeIdentity::from_seed_and_role(&seed, NodeRole::Voter));
    let node_pubkey = identity.verifying_key().to_bytes();

    let phonebook = test_phonebook(&node_pubkey);
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db))
        .with_identity(Arc::clone(&identity));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Helper closure to send command and receive response over Unix stream
    async fn send_cmd(socket_path: &std::path::Path, cmd: &IpcCommand) -> IpcResponse {
        let stream = UnixStream::connect(socket_path).await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);

        let cmd_line = serde_json::to_string(cmd).unwrap() + "\n";
        writer.write_all(cmd_line.as_bytes()).await.unwrap();

        let mut resp_line = String::new();
        buf_reader.read_line(&mut resp_line).await.unwrap();
        serde_json::from_str(&resp_line).unwrap()
    }

    // 1. Publish CA
    let ca_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Rotation IPC Root CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("ES".to_string()),
        email: None,
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: None,
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        permitted_subtrees: None,
    };
    let ca_resp = send_cmd(&socket_path, &ca_cmd).await;
    let ca_id_hex = match ca_resp {
        IpcResponse::Ok { message } => message.split('`').nth(3).unwrap().to_string(),
        _ => panic!("Expected successful CA publish"),
    };

    // 2. Publish Offer 0 and Offer 1
    let offer0_cmd = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(0),
        name: "Standard Tier 0".to_string(),
        key_algorithm: Some(KeyAlgorithm::Ed25519),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(864000),
        coverage_scope: None,
        is_draft: None,
    };
    assert!(matches!(
        send_cmd(&socket_path, &offer0_cmd).await,
        IpcResponse::Ok { .. }
    ));

    let offer1_cmd = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(1),
        name: "Standard Tier 1".to_string(),
        key_algorithm: Some(KeyAlgorithm::Ed25519),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(864000),
        coverage_scope: None,
        is_draft: None,
    };
    assert!(matches!(
        send_cmd(&socket_path, &offer1_cmd).await,
        IpcResponse::Ok { .. }
    ));

    // 3. Record Distrust Strike
    let strike_cmd = IpcCommand::RecordDistrustStrike {
        ca_id_hex: ca_id_hex.clone(),
        reason: Some("Key leakage reported".to_string()),
    };
    let strike_resp = send_cmd(&socket_path, &strike_cmd).await;
    assert!(matches!(strike_resp, IpcResponse::Ok { .. }));

    // 4. Query Distrust Status
    let status_cmd = IpcCommand::GetCaDistrustStatus {
        ca_id_hex: ca_id_hex.clone(),
    };
    let status_resp = send_cmd(&socket_path, &status_cmd).await;
    match status_resp {
        IpcResponse::Ok { message } => {
            let val: serde_json::Value = serde_json::from_str(&message).unwrap();
            assert_eq!(val["standing_distrust_strikes"], 1);
            assert_eq!(val["has_standing_distrust"], true);
        }
        _ => panic!("Expected status response"),
    }

    // 5. Partial Key Rotation (Offer 0 only)
    let rot_partial_cmd = IpcCommand::PublishKeyRotation {
        ca_id_hex: ca_id_hex.clone(),
        reason: Some("leakage".to_string()),
        offer_id: Some(0),
        proof_json: None,
    };
    let rot_partial_resp = send_cmd(&socket_path, &rot_partial_cmd).await;
    match rot_partial_resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("partial rotation"));
        }
        _ => panic!("Expected partial rotation response"),
    }

    // Verify distrust STILL stands after partial rotation
    let status_resp2 = send_cmd(&socket_path, &status_cmd).await;
    match status_resp2 {
        IpcResponse::Ok { message } => {
            let val: serde_json::Value = serde_json::from_str(&message).unwrap();
            assert_eq!(val["standing_distrust_strikes"], 1);
            assert_eq!(val["has_standing_distrust"], true);
            assert_eq!(val["key_rotations_count"], 1);
        }
        _ => panic!("Expected status response"),
    }

    // 6. Full Remediation Key Rotation (All offers rotated)
    let rot_full_cmd = IpcCommand::PublishKeyRotation {
        ca_id_hex: ca_id_hex.clone(),
        reason: Some("remediation".to_string()),
        offer_id: None, // rotates all active offers!
        proof_json: None,
    };
    let rot_full_resp = send_cmd(&socket_path, &rot_full_cmd).await;
    match rot_full_resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("Distrust remediated and strikes reset to 0"));
        }
        _ => panic!("Expected full remediation response"),
    }

    // 7. Verify distrust is now CLEAN (0 strikes, has_standing_distrust == false)
    let status_resp3 = send_cmd(&socket_path, &status_cmd).await;
    match status_resp3 {
        IpcResponse::Ok { message } => {
            let val: serde_json::Value = serde_json::from_str(&message).unwrap();
            assert_eq!(val["standing_distrust_strikes"], 0);
            assert_eq!(val["has_standing_distrust"], false);
            assert_eq!(val["key_rotations_count"], 2);
        }
        _ => panic!("Expected status response"),
    }

    // 8. Query Rotation Audit Trail
    let audit_cmd = IpcCommand::GetKeyRotations {
        ca_id_hex: ca_id_hex.clone(),
    };
    let audit_resp = send_cmd(&socket_path, &audit_cmd).await;
    match audit_resp {
        IpcResponse::Ok { message } => {
            let proofs: Vec<KeyRotationProof> = serde_json::from_str(&message).unwrap();
            assert_eq!(proofs.len(), 2);
            assert_eq!(proofs[0].rotation_seq, 1);
            assert_eq!(proofs[1].rotation_seq, 2);
            assert_eq!(proofs[1].prev_rotation_hash, proofs[0].proof_id);
        }
        _ => panic!("Expected audit response"),
    }

    handle.abort();
    let _ = std::fs::remove_dir_all(&temp_dir);
}
