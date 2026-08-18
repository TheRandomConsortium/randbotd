use super::*;
use crate::crypto::agility::KeyAlgorithm;
use crate::pki::offer::CertificateOffer;
use crate::proof::DomainNetworkType;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

#[tokio::test]
async fn test_ipc_command_import_peer_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let server = IpcServer::new(socket_path.clone(), Arc::clone(&phonebook));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to IPC socket");
    let (reader, mut writer) = stream.into_split();

    let cmd = IpcCommand::ImportPeer {
        peer_addr: "127.0.0.1:43210".to_string(),
    };
    let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
    writer.write_all(cmd_line.as_bytes()).await.unwrap();

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader.read_line(&mut resp_line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
    match resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("127.0.0.1:43210"));
        }
        _ => panic!("Expected IpcResponse::Ok"),
    }

    let pb = phonebook.read().unwrap();
    assert!(pb.all_peers().contains(&"127.0.0.1:43210".to_string()));

    handle.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn test_ipc_publish_ca_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_ca_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = UnixStream::connect(&socket_path)
        .await
        .expect("Failed to connect to IPC socket");
    let (reader, mut writer) = stream.into_split();

    let cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "The Random Consortium Root CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: Some("PKI".to_string()),
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: Some("root@consortium.rand".to_string()),
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: None,
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
    };
    let cmd_line = serde_json::to_string(&cmd).unwrap() + "\n";
    writer.write_all(cmd_line.as_bytes()).await.unwrap();

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader.read_line(&mut resp_line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
    match resp {
        IpcResponse::Ok { message } => {
            assert!(message
                .contains("CA Declaration `The Random Consortium Root CA` successfully published"));
        }
        _ => panic!("Expected IpcResponse::Ok, got {:?}", resp),
    }

    let cas = db.list_cas();
    assert_eq!(cas.len(), 1);
    assert_eq!(cas[0].subject.common_name, "The Random Consortium Root CA");
    assert!(!cas[0].is_draft);

    handle.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn test_ipc_ca_draft_and_edit_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_draft_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    // 1. Create a draft CA
    let draft_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Consortium Draft CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: None,
        state_or_province: None,
        country: Some("ES".to_string()),
        email: None,
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: Some(true),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
    };
    let cmd_line = serde_json::to_string(&draft_cmd).unwrap() + "\n";
    writer.write_all(cmd_line.as_bytes()).await.unwrap();

    let mut buf_reader = BufReader::new(reader);
    let mut resp_line = String::new();
    buf_reader.read_line(&mut resp_line).await.unwrap();

    let resp: IpcResponse = serde_json::from_str(&resp_line).unwrap();
    let ca_id_hex = match resp {
        IpcResponse::Ok { message } => {
            assert!(message.contains("draft saved"));
            message.split('`').nth(3).unwrap().to_string()
        }
        _ => panic!("Expected Ok response"),
    };

    let cas = db.list_cas();
    assert_eq!(cas.len(), 1);
    assert!(cas[0].is_draft);

    // 2. Edit existing draft CA and finalize publish (is_draft = false)
    let stream2 = UnixStream::connect(&socket_path).await.unwrap();
    let (reader2, mut writer2) = stream2.into_split();

    let edit_cmd = IpcCommand::PublishCa {
        ca_id_hex: Some(ca_id_hex.clone()),
        common_name: "Consortium Final CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: Some("PKI Operations".to_string()),
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: Some("ca@therandomconsortium.org".to_string()),
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: Some(false),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
    };
    let edit_line = serde_json::to_string(&edit_cmd).unwrap() + "\n";
    writer2.write_all(edit_line.as_bytes()).await.unwrap();

    let mut buf_reader2 = BufReader::new(reader2);
    let mut resp_line2 = String::new();
    buf_reader2.read_line(&mut resp_line2).await.unwrap();

    let resp2: IpcResponse = serde_json::from_str(&resp_line2).unwrap();
    match resp2 {
        IpcResponse::Ok { message } => {
            assert!(message.contains("successfully published"));
        }
        _ => panic!("Expected Ok response for edit"),
    }

    let cas_updated = db.list_cas();
    assert_eq!(cas_updated.len(), 1);
    assert_eq!(cas_updated[0].subject.common_name, "Consortium Final CA");
    assert!(!cas_updated[0].is_draft);

    handle.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn test_ipc_publish_offer_and_catalog_queries_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_offer_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 1. Create a CA
    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();

    let ca_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Catalog Root CA".to_string(),
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
    };
    let ca_line = serde_json::to_string(&ca_cmd).unwrap() + "\n";
    writer.write_all(ca_line.as_bytes()).await.unwrap();

    let mut buf_reader = BufReader::new(reader);
    let mut ca_resp_line = String::new();
    buf_reader.read_line(&mut ca_resp_line).await.unwrap();

    let ca_resp: IpcResponse = serde_json::from_str(&ca_resp_line).unwrap();
    let ca_id_hex = match ca_resp {
        IpcResponse::Ok { message } => message.split('`').nth(3).unwrap().to_string(),
        _ => panic!("Expected CA publish Ok"),
    };

    // 2. Publish Offer 0 (Standard 90-day Clearnet)
    let stream2 = UnixStream::connect(&socket_path).await.unwrap();
    let (reader2, mut writer2) = stream2.into_split();

    let offer_cmd = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(0),
        name: "Standard Clearnet 90-day".to_string(),
        key_algorithm: Some(KeyAlgorithm::Ed25519),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(7_776_000),
        is_draft: None,
    };
    let offer_line = serde_json::to_string(&offer_cmd).unwrap() + "\n";
    writer2.write_all(offer_line.as_bytes()).await.unwrap();

    let mut buf_reader2 = BufReader::new(reader2);
    let mut offer_resp_line = String::new();
    buf_reader2.read_line(&mut offer_resp_line).await.unwrap();

    let offer_resp: IpcResponse = serde_json::from_str(&offer_resp_line).unwrap();
    match offer_resp {
        IpcResponse::Ok { message } => {
            assert!(
                message.contains("Offer `Standard Clearnet 90-day` (ID 0) successfully published")
            );
        }
        _ => panic!("Expected Offer publish Ok, got {:?}", offer_resp),
    }

    // 3. Query the Offer via GetOffer
    let stream3 = UnixStream::connect(&socket_path).await.unwrap();
    let (reader3, mut writer3) = stream3.into_split();

    let get_cmd = IpcCommand::GetOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: 0,
    };
    let get_line = serde_json::to_string(&get_cmd).unwrap() + "\n";
    writer3.write_all(get_line.as_bytes()).await.unwrap();

    let mut buf_reader3 = BufReader::new(reader3);
    let mut get_resp_line = String::new();
    buf_reader3.read_line(&mut get_resp_line).await.unwrap();

    let get_resp: IpcResponse = serde_json::from_str(&get_resp_line).unwrap();
    match get_resp {
        IpcResponse::Ok { message } => {
            let offer_retrieved: CertificateOffer = serde_json::from_str(&message).unwrap();
            assert_eq!(offer_retrieved.offer_id, 0);
            assert_eq!(offer_retrieved.name, "Standard Clearnet 90-day");
            assert_eq!(offer_retrieved.ttl_seconds, 7_776_000);
        }
        _ => panic!("Expected GetOffer Ok, got {:?}", get_resp),
    }

    // 4. Query ListOffers
    let stream4 = UnixStream::connect(&socket_path).await.unwrap();
    let (reader4, mut writer4) = stream4.into_split();

    let list_cmd = IpcCommand::ListOffers {
        ca_id_hex: Some(ca_id_hex.clone()),
    };
    let list_line = serde_json::to_string(&list_cmd).unwrap() + "\n";
    writer4.write_all(list_line.as_bytes()).await.unwrap();

    let mut buf_reader4 = BufReader::new(reader4);
    let mut list_resp_line = String::new();
    buf_reader4.read_line(&mut list_resp_line).await.unwrap();

    let list_resp: IpcResponse = serde_json::from_str(&list_resp_line).unwrap();
    match list_resp {
        IpcResponse::Ok { message } => {
            let offers: Vec<CertificateOffer> = serde_json::from_str(&message).unwrap();
            assert_eq!(offers.len(), 1);
            assert_eq!(offers[0].offer_id, 0);
        }
        _ => panic!("Expected ListOffers Ok, got {:?}", list_resp),
    }

    // 5. Verify CA has catalog hash & offer_ids updated in Database
    let ca_bytes = crate::storage::db::ca_subtable::hex_to_bytes32(&ca_id_hex).unwrap();
    let ca_in_db = db.get_ca(&ca_bytes).unwrap();
    assert!(ca_in_db.current_catalog_hash.is_some());
    assert_eq!(ca_in_db.offer_ids, vec![0]);

    handle.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}

#[tokio::test]
async fn test_ipc_multi_tier_offer_catalog_and_persistence_roundtrip() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_ipc_multioffer_test_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = Arc::new(RwLock::new(Phonebook::new()));
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // 1. Create a Multi-Network Root CA
    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let ca_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Enterprise Multi-Tier CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: Some("PKI Multi-Tier".to_string()),
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: Some("enterprise@consortium.rand".to_string()),
        is_intermediate: false,
        path_len_constraint: None,
        is_draft: None,
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
    };
    writer
        .write_all((serde_json::to_string(&ca_cmd).unwrap() + "\n").as_bytes())
        .await
        .unwrap();

    let mut buf_reader = BufReader::new(reader);
    let mut ca_resp_line = String::new();
    buf_reader.read_line(&mut ca_resp_line).await.unwrap();
    let ca_resp: IpcResponse = serde_json::from_str(&ca_resp_line).unwrap();
    let ca_id_hex = match ca_resp {
        IpcResponse::Ok { message } => message.split('`').nth(3).unwrap().to_string(),
        _ => panic!("Expected CA publish Ok"),
    };

    // 2. Publish Profile 0: Free Standard (Ed25519, 90d)
    let stream_o0 = UnixStream::connect(&socket_path).await.unwrap();
    let (r0, mut w0) = stream_o0.into_split();
    let offer_0 = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(0),
        name: "Profile 0: Standard Free Tier".to_string(),
        key_algorithm: Some(KeyAlgorithm::Ed25519),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(7_776_000),
        is_draft: None,
    };
    w0.write_all((serde_json::to_string(&offer_0).unwrap() + "\n").as_bytes())
        .await
        .unwrap();
    let mut br0 = BufReader::new(r0);
    let mut resp0 = String::new();
    br0.read_line(&mut resp0).await.unwrap();
    assert!(resp0.contains("Profile 0: Standard Free Tier"));

    // 3. Publish Profile 1: ECDSA P-384 Tier (180d)
    let stream_o1 = UnixStream::connect(&socket_path).await.unwrap();
    let (r1, mut w1) = stream_o1.into_split();
    let offer_1 = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(1),
        name: "Profile 1: P-384 Wildcard Tier".to_string(),
        key_algorithm: Some(KeyAlgorithm::EcdsaP384),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(15_552_000),
        is_draft: None,
    };
    w1.write_all((serde_json::to_string(&offer_1).unwrap() + "\n").as_bytes())
        .await
        .unwrap();
    let mut br1 = BufReader::new(r1);
    let mut resp1 = String::new();
    br1.read_line(&mut resp1).await.unwrap();
    assert!(resp1.contains("Profile 1: P-384 Wildcard Tier"));

    // 4. Publish Profile 2: Quantum-Safe ML-DSA-44 Tier (365d)
    let stream_o2 = UnixStream::connect(&socket_path).await.unwrap();
    let (r2, mut w2) = stream_o2.into_split();
    let offer_2 = IpcCommand::PublishOffer {
        ca_id_hex: ca_id_hex.clone(),
        offer_id: Some(2),
        name: "Profile 2: Enterprise PQC Tier".to_string(),
        key_algorithm: Some(KeyAlgorithm::MlDsa44),
        supported_domain_networks: Some(vec![DomainNetworkType::Clearnet]),
        ttl_seconds: Some(31_536_000),
        is_draft: None,
    };
    w2.write_all((serde_json::to_string(&offer_2).unwrap() + "\n").as_bytes())
        .await
        .unwrap();
    let mut br2 = BufReader::new(r2);
    let mut resp2 = String::new();
    br2.read_line(&mut resp2).await.unwrap();
    assert!(resp2.contains("Profile 2: Enterprise PQC Tier"));

    // 5. Query ListOffers and verify all 3 profiles present
    let stream_list = UnixStream::connect(&socket_path).await.unwrap();
    let (rl, mut wl) = stream_list.into_split();
    let list_cmd = IpcCommand::ListOffers {
        ca_id_hex: Some(ca_id_hex.clone()),
    };
    wl.write_all((serde_json::to_string(&list_cmd).unwrap() + "\n").as_bytes())
        .await
        .unwrap();
    let mut brl = BufReader::new(rl);
    let mut respl = String::new();
    brl.read_line(&mut respl).await.unwrap();
    let list_resp: IpcResponse = serde_json::from_str(&respl).unwrap();
    let offers: Vec<CertificateOffer> = match list_resp {
        IpcResponse::Ok { message } => serde_json::from_str(&message).unwrap(),
        _ => panic!("Expected ListOffers Ok"),
    };
    assert_eq!(offers.len(), 3);
    assert_eq!(offers[0].offer_id, 0);
    assert_eq!(offers[1].offer_id, 1);
    assert_eq!(offers[2].offer_id, 2);

    // 6. Verify disk persistence across Database re-opens
    handle.abort();

    let db_reopened = Database::open(&temp_dir).unwrap();
    let ca_bytes = crate::storage::db::ca_subtable::hex_to_bytes32(&ca_id_hex).unwrap();
    let ca_loaded = db_reopened.get_ca(&ca_bytes).unwrap();
    assert_eq!(ca_loaded.offer_ids, vec![0, 1, 2]);
    assert!(ca_loaded.current_catalog_hash.is_some());

    let offers_loaded = db_reopened.list_offers_for_ca(&ca_bytes);
    assert_eq!(offers_loaded.len(), 3);
    assert_eq!(offers_loaded[0].name, "Profile 0: Standard Free Tier");
    assert_eq!(offers_loaded[1].name, "Profile 1: P-384 Wildcard Tier");
    assert_eq!(offers_loaded[2].name, "Profile 2: Enterprise PQC Tier");

    let _ = std::fs::remove_dir_all(temp_dir);
}
