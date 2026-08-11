use super::*;
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn test_database_event_log_roundtrip() {
    use rand::RngCore;
    let temp_dir = std::env::temp_dir().join(format!("randbotd_db_test_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    let seq = 1u64;
    let prev_hash = [0x00u8; 32];
    let payload_type = 0x02u8;
    let payload = b"TW_vote_db_test".to_vec();

    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&seq.to_be_bytes());
    signed_data.extend_from_slice(&prev_hash);
    signed_data.push(payload_type);
    signed_data.extend_from_slice(&payload);
    let sig_bytes = signing_key.sign(&signed_data).to_bytes().to_vec();

    let entry =
        EventLogEntry::new(seq, prev_hash, originator, payload_type, payload, sig_bytes).unwrap();
    assert!(db.append_event(entry).is_ok());

    let loaded_db = Database::open(&temp_dir).expect("Failed to re-open DB");
    let log = loaded_db.event_log.read().unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].seq, 1);

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_database_per_originator_interleaved_events() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_db_interleaved_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let secret_a = [0x01u8; 32];
    let signing_key_a = SigningKey::from_bytes(&secret_a);
    let originator_a = signing_key_a.verifying_key().to_bytes();

    let secret_b = [0x02u8; 32];
    let signing_key_b = SigningKey::from_bytes(&secret_b);
    let originator_b = signing_key_b.verifying_key().to_bytes();

    let mut data_a1 = Vec::new();
    data_a1.extend_from_slice(&1u64.to_be_bytes());
    data_a1.extend_from_slice(&[0u8; 32]);
    data_a1.push(0x02);
    data_a1.extend_from_slice(b"vote_a1");
    let sig_a1 = signing_key_a.sign(&data_a1).to_bytes().to_vec();
    let entry_a1 = EventLogEntry::new(
        1,
        [0u8; 32],
        originator_a,
        0x02,
        b"vote_a1".to_vec(),
        sig_a1,
    )
    .unwrap();
    db.append_event(entry_a1.clone()).unwrap();

    let mut data_b1 = Vec::new();
    data_b1.extend_from_slice(&1u64.to_be_bytes());
    data_b1.extend_from_slice(&[0u8; 32]);
    data_b1.push(0x02);
    data_b1.extend_from_slice(b"vote_b1");
    let sig_b1 = signing_key_b.sign(&data_b1).to_bytes().to_vec();
    let entry_b1 = EventLogEntry::new(
        1,
        [0u8; 32],
        originator_b,
        0x02,
        b"vote_b1".to_vec(),
        sig_b1,
    )
    .unwrap();
    db.append_event(entry_b1).unwrap();

    let prev_hash_a1 = entry_a1.compute_hash();
    let mut data_a2 = Vec::new();
    data_a2.extend_from_slice(&2u64.to_be_bytes());
    data_a2.extend_from_slice(&prev_hash_a1);
    data_a2.push(0x02);
    data_a2.extend_from_slice(b"vote_a2");
    let sig_a2 = signing_key_a.sign(&data_a2).to_bytes().to_vec();
    let entry_a2 = EventLogEntry::new(
        2,
        prev_hash_a1,
        originator_a,
        0x02,
        b"vote_a2".to_vec(),
        sig_a2,
    )
    .unwrap();
    db.append_event(entry_a2).unwrap();

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_database_out_of_order_staging_and_autopromote() {
    let temp_dir = std::env::temp_dir().join(format!("randbotd_db_ooo_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let secret = [0x09u8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    let mut d1 = Vec::new();
    d1.extend_from_slice(&1u64.to_be_bytes());
    d1.extend_from_slice(&[0u8; 32]);
    d1.push(0x02);
    d1.extend_from_slice(b"p1");
    let sig1 = signing_key.sign(&d1).to_bytes().to_vec();
    let e1 = EventLogEntry::new(1, [0u8; 32], originator, 0x02, b"p1".to_vec(), sig1).unwrap();
    let h1 = e1.compute_hash();

    let mut d2 = Vec::new();
    d2.extend_from_slice(&2u64.to_be_bytes());
    d2.extend_from_slice(&h1);
    d2.push(0x02);
    d2.extend_from_slice(b"p2");
    let sig2 = signing_key.sign(&d2).to_bytes().to_vec();
    let e2 = EventLogEntry::new(2, h1, originator, 0x02, b"p2".to_vec(), sig2).unwrap();

    assert!(db.append_event(e2.clone()).is_ok());
    {
        let log = db.event_log.read().unwrap();
        assert_eq!(log.len(), 0);
    }
    {
        let pending = db.pending_unverified.read().unwrap();
        assert_eq!(pending.get(&originator).unwrap().len(), 1);
    }

    assert!(db.append_event(e1.clone()).is_ok());
    {
        let log = db.event_log.read().unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);
    }
    {
        let pending = db.pending_unverified.read().unwrap();
        assert!(pending.get(&originator).unwrap().is_empty());
    }

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_database_bullshit_event_ingestion_and_reputation() {
    let temp_dir = std::env::temp_dir().join(format!("randbotd_db_bs_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let secret = [0x0Bu8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    let mut d1 = Vec::new();
    d1.extend_from_slice(&1u64.to_be_bytes());
    d1.extend_from_slice(&[0u8; 32]);
    d1.push(0x02);
    d1.extend_from_slice(b"good_payload");
    let sig1 = signing_key.sign(&d1).to_bytes().to_vec();
    let e1 = EventLogEntry::new(
        1,
        [0u8; 32],
        originator,
        0x02,
        b"good_payload".to_vec(),
        sig1,
    )
    .unwrap();
    assert!(db.append_event(e1).is_ok());

    let mut d2 = Vec::new();
    d2.extend_from_slice(&2u64.to_be_bytes());
    d2.extend_from_slice(&[0xFFu8; 32]);
    d2.push(0x02);
    d2.extend_from_slice(b"bad_payload");
    let sig2 = signing_key.sign(&d2).to_bytes().to_vec();
    let e2 = EventLogEntry::new(
        2,
        [0xFFu8; 32],
        originator,
        0x02,
        b"bad_payload".to_vec(),
        sig2,
    )
    .unwrap();
    assert!(db.append_event(e2).is_ok());

    let (valid, bs) = db.get_originator_reputation(&originator);
    assert_eq!(valid, 1);
    assert_eq!(bs, 1);

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_database_max_staged_events_oom_prevention() {
    let temp_dir = std::env::temp_dir().join(format!("randbotd_db_oom_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let secret = [0x0Cu8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    // Push 60 out-of-order events (seq 10..70)
    for i in 10..70u64 {
        let mut d = Vec::new();
        d.extend_from_slice(&i.to_be_bytes());
        d.extend_from_slice(&[0u8; 32]);
        d.push(0x02);
        d.extend_from_slice(b"payload");
        let sig = signing_key.sign(&d).to_bytes().to_vec();
        let e =
            EventLogEntry::new(i, [0u8; 32], originator, 0x02, b"payload".to_vec(), sig).unwrap();
        let _ = db.append_event(e);
    }

    let pending = db.pending_unverified.read().unwrap();
    assert_eq!(pending.get(&originator).unwrap().len(), MAX_STAGED_EVENTS);
    assert_eq!(MAX_STAGED_EVENTS, 50);

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_database_equivocation_truth_resolution() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_db_eq_truth_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let secret = [0x0Du8; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let originator = signing_key.verifying_key().to_bytes();

    // 1. Valid seq 1
    let mut d1 = Vec::new();
    d1.extend_from_slice(&1u64.to_be_bytes());
    d1.extend_from_slice(&[0u8; 32]);
    d1.push(0x02);
    d1.extend_from_slice(b"seq1");
    let sig1 = signing_key.sign(&d1).to_bytes().to_vec();
    let e1 = EventLogEntry::new(1, [0u8; 32], originator, 0x02, b"seq1".to_vec(), sig1).unwrap();
    let h1 = e1.compute_hash();
    assert!(db.append_event(e1).is_ok());

    // 2. Bullshit seq 2 (fake prev_hash)
    let mut d2_bs = Vec::new();
    d2_bs.extend_from_slice(&2u64.to_be_bytes());
    d2_bs.extend_from_slice(&[0xEEu8; 32]); // Fake prev_hash!
    d2_bs.push(0x02);
    d2_bs.extend_from_slice(b"bs_seq2");
    let sig2_bs = signing_key.sign(&d2_bs).to_bytes().to_vec();
    let e2_bs = EventLogEntry::new(
        2,
        [0xEEu8; 32],
        originator,
        0x02,
        b"bs_seq2".to_vec(),
        sig2_bs,
    )
    .unwrap();
    assert!(db.append_event(e2_bs).is_ok());

    // Verify bs_seq2 was ingested as bullshit
    {
        let log = db.event_log.read().unwrap();
        assert_eq!(log.len(), 2);
        assert!(log[1].is_bullshit);
    }

    // 3. True seq 2 arrives (valid prev_hash = h1)
    let mut d2_true = Vec::new();
    d2_true.extend_from_slice(&2u64.to_be_bytes());
    d2_true.extend_from_slice(&h1); // Valid prev_hash!
    d2_true.push(0x02);
    d2_true.extend_from_slice(b"true_seq2");
    let sig2_true = signing_key.sign(&d2_true).to_bytes().to_vec();
    let e2_true =
        EventLogEntry::new(2, h1, originator, 0x02, b"true_seq2".to_vec(), sig2_true).unwrap();
    let h2_true = e2_true.compute_hash();
    assert!(db.append_event(e2_true).is_ok());

    // Verify Truth Resolution & EquivocationProof recorded!
    {
        let log = db.event_log.read().unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log[1].seq, 2);
        assert_eq!(log[1].compute_hash(), h2_true); // Truth replaced bullshit at index 1!
        assert!(!log[1].is_bullshit); // Valid truth!
        assert_eq!(
            log[2].payload_type,
            crate::net::gossip::PAYLOAD_TYPE_EQUIVOCATION_PROOF
        );
    }
    let mut d3_true = Vec::new();
    d3_true.extend_from_slice(&3u64.to_be_bytes());
    d3_true.extend_from_slice(&h2_true); // Valid prev_hash linking to true seq 2!
    d3_true.push(0x02);
    d3_true.extend_from_slice(b"true_seq3");
    let sig3_true = signing_key.sign(&d3_true).to_bytes().to_vec();
    let e3_true = EventLogEntry::new(
        3,
        h2_true,
        originator,
        0x02,
        b"true_seq3".to_vec(),
        sig3_true,
    )
    .unwrap();
    assert!(db.append_event(e3_true).is_ok());

    {
        let log = db.event_log.read().unwrap();
        assert_eq!(log.len(), 4);
        assert_eq!(log[3].seq, 3);
        assert_eq!(log[3].prev_hash, h2_true);
        assert!(!log[3].is_bullshit); // Valid seq 3!
    }

    let (valid, bs) = db.get_originator_reputation(&originator);
    assert_eq!(valid, 3); // seq 1 + seq 2 true + seq 3 true
    assert_eq!(bs, 1); // EquivocationProof penalty!

    let _ = std::fs::remove_dir_all(temp_dir);
}

#[test]
fn test_db_ca_subtable_persistence() {
    use crate::crypto::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};

    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_ca_db_test_{}", rand::random::<u64>()));
    let db = Database::open(&temp_dir).expect("Failed to open DB");

    let subject = CaSubjectMetadata {
        common_name: "Consortium Root CA".to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: Some("PKI".to_string()),
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: Some("root@consortium.rand".to_string()),
    };

    let ca_id = compute_ca_id(b"root_key_bytes");
    let decl = CaDeclaration::new(
        ca_id,
        subject.clone(),
        subject.clone(),
        false,
        None,
        1700000000,
    )
    .unwrap();

    let inserted_id = db.insert_ca(decl.clone()).unwrap();
    assert_eq!(inserted_id, ca_id);

    let retrieved = db.get_ca(&ca_id).expect("Failed to get CA from DB");
    assert_eq!(retrieved, decl);

    let all_cas = db.list_cas();
    assert_eq!(all_cas.len(), 1);
    assert_eq!(all_cas[0].subject.common_name, "Consortium Root CA");

    // Close and reopen DB to verify JSON persistence
    drop(db);
    let db_reopened = Database::open(&temp_dir).expect("Failed to reopen DB");
    let retrieved_reopened = db_reopened
        .get_ca(&ca_id)
        .expect("Failed to get CA from reopened DB");
    assert_eq!(retrieved_reopened, decl);

    let _ = std::fs::remove_dir_all(temp_dir);
}
