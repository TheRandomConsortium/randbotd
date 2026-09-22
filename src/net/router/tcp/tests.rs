use super::*;

#[tokio::test]
async fn test_tcp_certificate_streaming_roundtrip() {
    let store = new_mock_cert_store();
    let sample_cert = b"-----BEGIN CERTIFICATE-----\nMOCK_QUANTUM_READY_CERTIFICATE_BODY\n-----END CERTIFICATE-----\n".to_vec();

    let mut hasher = Sha256::new();
    hasher.update(&sample_cert);
    let cert_hash: [u8; 32] = hasher.finalize().into();

    store
        .write()
        .unwrap()
        .insert(cert_hash, sample_cert.clone());

    let server = CertificateTcpServer::bind("127.0.0.1:0", store)
        .await
        .expect("Server bind failed");
    let addr = server.local_addr().unwrap();
    let _handle = server.spawn();

    let fetched = CertificateTcpClient::fetch_mock_cert(&addr.to_string(), &cert_hash)
        .await
        .expect("Fetch failed");

    assert_eq!(fetched, sample_cert);
}

#[tokio::test]
async fn test_tcp_quantum_sized_payload_transfer() {
    let store = new_mock_cert_store();
    // Simulate a 5.5 KB Post-Quantum ML-DSA-44 X.509 certificate
    let large_pqc_cert = vec![0x7au8; 5500];

    let mut hasher = Sha256::new();
    hasher.update(&large_pqc_cert);
    let cert_hash: [u8; 32] = hasher.finalize().into();

    store
        .write()
        .unwrap()
        .insert(cert_hash, large_pqc_cert.clone());

    let server = CertificateTcpServer::bind("127.0.0.1:0", store)
        .await
        .expect("Server bind failed");
    let addr = server.local_addr().unwrap();
    let _handle = server.spawn();

    let fetched = CertificateTcpClient::fetch_mock_cert(&addr.to_string(), &cert_hash)
        .await
        .expect("Fetch failed");

    assert_eq!(fetched.len(), 5500);
    assert_eq!(fetched, large_pqc_cert);
}

#[tokio::test]
async fn test_tcp_certificate_not_found() {
    let store = new_mock_cert_store();
    let nonexistent_hash = [0xffu8; 32];

    let server = CertificateTcpServer::bind("127.0.0.1:0", store)
        .await
        .expect("Server bind failed");
    let addr = server.local_addr().unwrap();
    let _handle = server.spawn();

    let result = CertificateTcpClient::fetch_mock_cert(&addr.to_string(), &nonexistent_hash).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Server returned non-OK status"));
}

#[tokio::test]
async fn test_tcp_hash_mismatch_detection() {
    let store = new_mock_cert_store();
    let sample_cert = b"Correct Certificate Data".to_vec();
    let query_hash = [0x55u8; 32];

    // Server has mismatched data stored under this hash
    store.write().unwrap().insert(query_hash, sample_cert);

    let server = CertificateTcpServer::bind("127.0.0.1:0", store)
        .await
        .expect("Server bind failed");
    let addr = server.local_addr().unwrap();
    let _handle = server.spawn();

    let result = CertificateTcpClient::fetch_mock_cert(&addr.to_string(), &query_hash).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("Integrity check failed: mock_cert_hash mismatch"));
}
