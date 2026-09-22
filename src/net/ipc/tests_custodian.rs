use std::sync::{Arc, RwLock};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::crypto::agility::KeyAlgorithm;
use crate::crypto::identity::{NodeIdentity, NodeRole};
use crate::net::ipc::{IpcCommand, IpcResponse, IpcServer};
use crate::net::phonebook::Phonebook;
use crate::net::router::tcp::{new_mock_cert_store, CertificateTcpClient, CertificateTcpServer};
use crate::pki::swarm::{
    CACapabilitiesProof, CustodianContract, CustodianDelegationRequest, CustodianSwarmRecord,
    SwarmActivationConfirmation,
};
use crate::proof::DomainNetworkType;
use crate::storage::db::Database;
use sha2::{Digest, Sha256};

fn test_phonebook(pubkey: &[u8; 32]) -> Arc<RwLock<Phonebook>> {
    let mut pb = Phonebook::new();
    pb.set_my_pubkey(pubkey);
    Arc::new(RwLock::new(pb))
}

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

#[tokio::test]
async fn test_ipc_custodian_lifecycle_and_policy() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_ipc_custodian_test_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let seed = [88u8; 32];
    let identity = Arc::new(NodeIdentity::from_seed_and_role(&seed, NodeRole::Voter));
    let node_pubkey = identity.verifying_key().to_bytes();

    let phonebook = test_phonebook(&node_pubkey);
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db))
        .with_identity(Arc::clone(&identity));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 1. Publish CA
    let ca_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Swarm Custodian Root CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("IS".to_string()),
        email: None,
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: Some(false),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        permitted_subtrees: None,
    };

    let resp = send_cmd(&socket_path, &ca_cmd).await;
    let ca_id_hex = match resp {
        IpcResponse::Ok { message } => message
            .split("with ca_id `")
            .nth(1)
            .unwrap()
            .split('`')
            .next()
            .unwrap()
            .to_string(),
        _ => panic!("Expected Ok response when creating CA: {:?}", resp),
    };

    // 2. Configure blind custodian policy
    let policy_cmd = IpcCommand::ConfigureCustodianPolicy {
        ca_id_hex: ca_id_hex.clone(),
        max_work_share_pct: 25,
        min_ttl_seconds: 3600,
        target_swarm_size: 4,
        auto_accept: true,
    };
    let resp = send_cmd(&socket_path, &policy_cmd).await;
    match resp {
        IpcResponse::Ok { message } => assert!(message.contains("max 25%")),
        _ => panic!("ConfigureCustodianPolicy failed: {:?}", resp),
    }

    // 3. Toggle seeking_custodians to true
    let seeking_cmd = IpcCommand::SetSeekingCustodians {
        ca_id_hex: ca_id_hex.clone(),
        seeking: true,
    };
    let resp = send_cmd(&socket_path, &seeking_cmd).await;
    match resp {
        IpcResponse::Ok { message } => assert!(message.contains("seeking_custodians = true")),
        _ => panic!("SetSeekingCustodians failed: {:?}", resp),
    }

    // 4. Candidate worker publishes CustodianContract
    let contract_cmd = IpcCommand::PublishCustodianContract {
        ca_id_hex: ca_id_hex.clone(),
        work_share_pct: 20,
        valid_until: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200,
        tcp_endpoint: "127.0.0.1:43210".to_string(),
    };
    let resp = send_cmd(&socket_path, &contract_cmd).await;
    match resp {
        IpcResponse::Ok { message } => assert!(message.contains("Published CustodianContract")),
        _ => panic!("PublishCustodianContract failed: {:?}", resp),
    }

    // 5. Test Swarm record insertion & ListCustodians
    let ca_id = crate::storage::db::ca_subtable::hex_to_bytes32(&ca_id_hex).unwrap();
    let worker_pubkey = [0x55u8; 32];
    let worker_hex = crate::storage::db::ca_subtable::bytes32_to_hex(&worker_pubkey);
    let record = CustodianSwarmRecord {
        ca_id,
        worker_pubkey,
        work_share_pct: 20,
        tcp_endpoint: "127.0.0.1:43210".to_string(),
        activated_at: 1000,
        contract_hash: [0x11u8; 32],
        mock_cert_hash: [0x22u8; 32],
    };
    db.insert_custodian_record(record).unwrap();

    let list_cmd = IpcCommand::ListCustodians {
        ca_id_hex: ca_id_hex.clone(),
    };
    let resp = send_cmd(&socket_path, &list_cmd).await;
    match resp {
        IpcResponse::Ok { message } => assert!(message.contains("127.0.0.1:43210")),
        _ => panic!("ListCustodians failed: {:?}", resp),
    }

    // 6. Test RemoveCustodian
    let remove_cmd = IpcCommand::RemoveCustodian {
        ca_id_hex: ca_id_hex.clone(),
        worker_pubkey_hex: worker_hex.clone(),
    };
    let resp = send_cmd(&socket_path, &remove_cmd).await;
    match resp {
        IpcResponse::Ok { message } => assert!(message.contains("Successfully removed custodian")),
        _ => panic!("RemoveCustodian failed: {:?}", resp),
    }

    handle.abort();
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_end_to_end_delegation_with_tcp_mock_cert_transfer() {
    let mock_store = new_mock_cert_store();
    let sample_pqc_cert = b"-----BEGIN CERTIFICATE-----\nML-DSA-44_POST_QUANTUM_MOCK_CERTIFICATE_PAYLOAD_EXCEEDING_UDP_MTU\n-----END CERTIFICATE-----\n".to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&sample_pqc_cert);
    let mock_cert_hash: [u8; 32] = hasher.finalize().into();

    mock_store
        .write()
        .unwrap()
        .insert(mock_cert_hash, sample_pqc_cert.clone());

    // Worker node runs TCP certificate server
    let tcp_server = CertificateTcpServer::bind("127.0.0.1:0", mock_store)
        .await
        .unwrap();
    let worker_tcp_addr = tcp_server.local_addr().unwrap();
    let _tcp_handle = tcp_server.spawn();

    // 1. Worker creates CustodianContract
    let worker_sk = ed25519_dalek::SigningKey::from_bytes(&[0xaa; 32]);
    let ca_sk = ed25519_dalek::SigningKey::from_bytes(&[0xbb; 32]);
    let ca_pubkey = ca_sk.verifying_key().to_bytes();
    let ca_id = [0x99u8; 32];

    let contract = CustodianContract::new(
        ca_id,
        &worker_sk,
        25,
        1000,
        5000,
        worker_tcp_addr.to_string(),
    )
    .unwrap();
    let contract_hash = contract.contract_hash();

    // 2. CA issues challenge
    let challenge = CustodianDelegationRequest::new(
        ca_id,
        contract.worker_pubkey,
        contract_hash,
        777777,
        1,
        &ca_sk,
    );
    assert!(challenge.verify_signature(&ca_pubkey).is_ok());

    // 3. Worker emits CACapabilitiesProof
    let proof = CACapabilitiesProof::new(
        ca_id,
        &worker_sk,
        contract_hash,
        mock_cert_hash,
        KeyAlgorithm::MlDsa44,
        sample_pqc_cert.len() as u32,
    );
    assert!(proof.verify_signature().is_ok());

    // 4. CA fetches mock cert over TCP
    let fetched_cert =
        CertificateTcpClient::fetch_mock_cert(&contract.tcp_endpoint, &proof.mock_cert_hash)
            .await
            .expect("TCP cert fetch should succeed");
    assert_eq!(fetched_cert, sample_pqc_cert);

    // 5. CA emits SwarmActivationConfirmation
    let confirmation = SwarmActivationConfirmation::new(
        ca_id,
        contract.worker_pubkey,
        contract_hash,
        mock_cert_hash,
        2000,
        &ca_sk,
    );
    assert!(confirmation
        .verify_against_contract(&contract, &ca_pubkey)
        .is_ok());
}
