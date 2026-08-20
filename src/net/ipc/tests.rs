use super::*;
use crate::proof::DomainNetworkType;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn test_phonebook() -> Arc<RwLock<Phonebook>> {
    let mut pb = Phonebook::new();
    pb.set_my_pubkey(&[42u8; 32]);
    Arc::new(RwLock::new(pb))
}

#[tokio::test]
async fn test_ipc_command_import_peer_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = test_phonebook();
    let server = IpcServer::new(socket_path.clone(), Arc::clone(&phonebook));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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

    let phonebook = test_phonebook();
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
        permitted_subtrees: None,
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

    let phonebook = test_phonebook();
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
        permitted_subtrees: None,
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
        permitted_subtrees: None,
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
async fn test_ipc_ca14_intermediate_ca_name_constraints_roundtrip() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ipc_ca14_test_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let socket_path = temp_dir.join("randbotd.sock");

    let phonebook = test_phonebook();
    let db = Arc::new(Database::open(&temp_dir).unwrap());
    let server = IpcServer::with_db(socket_path.clone(), Arc::clone(&phonebook), Arc::clone(&db));
    let handle = server.spawn();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Publish Intermediate CA with permitted_subtrees
    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (reader, mut writer) = stream.into_split();
    let ca_cmd = IpcCommand::PublishCa {
        ca_id_hex: None,
        common_name: "Handshake Subtree Intermediate CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: Some("Delegated PKI".to_string()),
        locality: None,
        state_or_province: None,
        country: Some("ES".to_string()),
        email: None,
        is_intermediate: true,
        path_len_constraint: Some(0),
        is_draft: None,
        supported_domain_networks: Some(vec![DomainNetworkType::Handshake]),
        permitted_subtrees: Some(vec!["community.hns".to_string()]),
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
        _ => panic!("Expected CA publish Ok, got {:?}", ca_resp),
    };

    let ca_bytes = crate::storage::db::ca_subtable::hex_to_bytes32(&ca_id_hex).unwrap();
    let ca_in_db = db.get_ca(&ca_bytes).unwrap();
    assert!(ca_in_db.is_intermediate);
    assert_eq!(
        ca_in_db.permitted_subtrees,
        vec!["community.hns".to_string()]
    );
    assert!(ca_in_db.is_domain_permitted("community.hns"));
    assert!(ca_in_db.is_domain_permitted("user.community.hns"));
    assert!(!ca_in_db.is_domain_permitted("otherdomain.org"));

    handle.abort();
    let _ = std::fs::remove_dir_all(temp_dir);
}
