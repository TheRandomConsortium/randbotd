use ed25519_dalek::SigningKey;
use std::sync::RwLock;

use crate::crypto::agility::{CaKeyPair, KeyAlgorithm};
use crate::crypto::vote::{VoteAction, VoteRecord};
use crate::net::phonebook::Phonebook;
use crate::pki::ca::{compute_ca_id, CaDeclaration, CaSubjectMetadata};
use crate::pki::cert::builder::X509CertificateBuilder;
use crate::pki::chain::CertificateChain;
use crate::pki::crl::{RevokedCertificateEntry, X509CrlBuilder};
use crate::pki::purge::{DomainPurgeRecord, PurgeReason};
use crate::storage::db::Database;

fn create_test_ca(common_name: &str) -> (CaDeclaration, CaKeyPair) {
    let subject = CaSubjectMetadata {
        common_name: common_name.to_string(),
        organization: Some("The Random Consortium".to_string()),
        organizational_unit: None,
        locality: Some("Valencia".to_string()),
        state_or_province: Some("Valencia".to_string()),
        country: Some("ES".to_string()),
        email: None,
    };
    let keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let ca_id = compute_ca_id(common_name, &keypair.public_key_bytes);
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
    (decl, keypair)
}

fn create_leaf_chain(
    ca_decl: &CaDeclaration,
    ca_keypair: &CaKeyPair,
    domain: &str,
    sans: Vec<String>,
) -> CertificateChain {
    let root_cert =
        X509CertificateBuilder::build_root_ca_certificate(ca_decl, ca_keypair, 864000, 1700000000)
            .unwrap();
    let leaf_keypair = CaKeyPair::generate(KeyAlgorithm::Ed25519).unwrap();
    let leaf_cert = X509CertificateBuilder::build_domain_leaf_certificate(
        ca_decl,
        ca_keypair,
        domain,
        KeyAlgorithm::Ed25519,
        &leaf_keypair.public_key_bytes,
        sans,
        86400,
        1700000000,
        None,
    )
    .unwrap();
    CertificateChain::new(leaf_cert, Vec::new(), Some(root_cert))
}

fn cast_vote_helper(
    db: &Database,
    domain: &str,
    action: VoteAction,
    signer: &SigningKey,
    timestamp: u64,
) -> VoteRecord {
    let pk = signer.verifying_key().to_bytes();
    let (prev_opt, active_count, revs) = db.get_vote_context(&pk, domain);
    let (seq, prev_hash) = match prev_opt {
        Some(p) => (p.vote_seq + 1, p.vote_id),
        None => (1, [0u8; 32]),
    };
    let vote = VoteRecord::new_signed(
        signer,
        domain,
        action,
        seq,
        prev_hash,
        timestamp,
        active_count,
        revs,
    )
    .unwrap();
    db.insert_vote(vote.clone()).unwrap();
    vote
}

#[test]
fn test_ca_rating_empty_ca_baseline() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_test_ca_empty_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Database::open(&temp_dir).unwrap();

    let (ca_decl, _) = create_test_ca("Empty Test CA");
    let ca_id = db.insert_ca(ca_decl).unwrap();

    let rating_eval = db.evaluate_ca_rating(&ca_id, None).unwrap();
    assert_eq!(rating_eval.rating, 50.0);
    assert_eq!(rating_eval.delta, 50.0);
    assert_eq!(rating_eval.lower_bound, 0.0);
    assert_eq!(rating_eval.upper_bound, 100.0);
    assert_eq!(rating_eval.total_issued_domains, 0);
    assert_eq!(rating_eval.active_domains_count, 0);
    assert_eq!(rating_eval.purged_domains_count, 0);
    assert_eq!(rating_eval.revoked_domains_count, 0);
    assert_eq!(rating_eval.total_ca_votes, 0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ca_rating_clean_domains_propagation() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_test_ca_clean_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Database::open(&temp_dir).unwrap();

    let (ca_decl, ca_keypair) = create_test_ca("Honest Enterprise CA");
    let ca_id = db.insert_ca(ca_decl.clone()).unwrap();

    // Issue cert chains for two domains
    let chain1 = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "shop.randbot.hns",
        vec!["shop.randbot.hns".into()],
    );
    let chain2 = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "pay.randbot.hns",
        vec!["pay.randbot.hns".into()],
    );
    db.insert_cert_chain(chain1).unwrap();
    db.insert_cert_chain(chain2).unwrap();

    // Register voters in phonebook
    let phonebook = RwLock::new(Phonebook::new());
    let mut voter_signers = Vec::new();
    for i in 1..=3 {
        let sk = SigningKey::from_bytes(&[i as u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        phonebook.write().unwrap().update_peer_ponderation(&pk, 80);
        voter_signers.push(sk);
    }

    // Cast TW votes on both domains
    let mut t = 1700000000;
    for voter in &voter_signers {
        t += 10;
        cast_vote_helper(&db, "shop.randbot.hns", VoteAction::Tw, voter, t);
        t += 10;
        cast_vote_helper(&db, "pay.randbot.hns", VoteAction::Tw, voter, t);
    }

    let eval = db.evaluate_ca_rating(&ca_id, Some(&phonebook)).unwrap();
    assert_eq!(eval.rating, 100.0);
    assert_eq!(eval.total_issued_domains, 2);
    assert_eq!(eval.active_domains_count, 2);
    assert_eq!(eval.total_ca_votes, 6);
    assert!(eval.delta < 50.0); // Delta narrowed due to 6 votes
    assert!(eval.lower_bound > 50.0);
    assert_eq!(eval.upper_bound, 100.0);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ca_rating_attacked_domain_and_purge_image_cleaning_rep06() {
    let temp_dir = std::env::temp_dir().join(format!(
        "randbotd_test_ca_purge_rep06_{}",
        rand::random::<u64>()
    ));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Database::open(&temp_dir).unwrap();

    let (ca_decl, ca_keypair) = create_test_ca("Vulnerable But Proactive CA");
    let ca_id = db.insert_ca(ca_decl.clone()).unwrap();

    // Issue cert chains for clean domain and bad domain
    let chain_clean = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "goodsite.randbot.hns",
        vec!["goodsite.randbot.hns".into()],
    );
    let chain_bad = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "phishing.randbot.hns",
        vec!["phishing.randbot.hns".into()],
    );
    db.insert_cert_chain(chain_clean).unwrap();
    db.insert_cert_chain(chain_bad).unwrap();

    let phonebook = RwLock::new(Phonebook::new());
    let mut voter_signers = Vec::new();
    for i in 10..=13 {
        let sk = SigningKey::from_bytes(&[i as u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        phonebook.write().unwrap().update_peer_ponderation(&pk, 70);
        voter_signers.push(sk);
    }

    let mut t = 1700000000;
    // Goodsite receives TW votes (100% trust)
    for voter in &voter_signers {
        t += 10;
        cast_vote_helper(&db, "goodsite.randbot.hns", VoteAction::Tw, voter, t);
    }
    // Phishing receives UTW votes (0% trust)
    for voter in &voter_signers {
        t += 10;
        cast_vote_helper(&db, "phishing.randbot.hns", VoteAction::Utw, voter, t);
    }

    // Pre-purge evaluation: CA rating is dragged down by phishing domain to 50.0%
    let pre_eval = db.evaluate_ca_rating(&ca_id, Some(&phonebook)).unwrap();
    assert_eq!(pre_eval.active_domains_count, 2);
    assert_eq!(pre_eval.rating, 50.0);
    assert_eq!(pre_eval.purged_domains_count, 0);

    // Operator executes Domain Purge (CA-07 / REP-06)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ca_secret_bytes: [u8; 32] = ca_keypair.private_key_bytes.as_slice().try_into().unwrap();
    let ca_signing_key = SigningKey::from_bytes(&ca_secret_bytes);
    let purge_record = DomainPurgeRecord::new(
        ca_id,
        "phishing.randbot.hns".to_string(),
        None,
        1,
        [0u8; 32],
        now,
        now + 86400,
        PurgeReason::MalwarePhishing,
        "Phishing domain identified and purged".to_string(),
        None,
        0,
        &ca_signing_key,
    )
    .unwrap();
    db.insert_purge(purge_record).unwrap();

    // Post-purge evaluation: On-demand query immediately excludes phishing domain!
    let post_eval = db.evaluate_ca_rating(&ca_id, Some(&phonebook)).unwrap();
    assert_eq!(post_eval.total_issued_domains, 2);
    assert_eq!(post_eval.active_domains_count, 1);
    assert_eq!(post_eval.purged_domains_count, 1);
    assert_eq!(post_eval.rating, 100.0); // CA rating restored to 100.0%!
    assert_eq!(
        post_eval.domain_evaluations[0].domain,
        "goodsite.randbot.hns"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ca_rating_revoked_cert_exclusion() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_test_ca_crl_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Database::open(&temp_dir).unwrap();

    let (ca_decl, ca_keypair) = create_test_ca("CRL Testing CA");
    let ca_id = db.insert_ca(ca_decl.clone()).unwrap();

    let chain = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "compromised.randbot.hns",
        vec!["compromised.randbot.hns".into()],
    );
    let leaf_serial = chain.target_certificate.serial_number.clone();
    db.insert_cert_chain(chain).unwrap();

    // Issue CRL revoking this certificate
    let crl = X509CrlBuilder::build_crl(
        &ca_decl,
        &ca_keypair,
        vec![RevokedCertificateEntry {
            serial_number: leaf_serial,
            revocation_date: 1700000010,
            reason: Some(crate::pki::crl::CRLReason::KeyCompromise),
        }],
        1700000000,
        1700086400,
        1,
    )
    .unwrap();
    db.insert_crl(crl).unwrap();

    let eval = db.evaluate_ca_rating(&ca_id, None).unwrap();
    assert_eq!(eval.active_domains_count, 0);
    assert_eq!(eval.revoked_domains_count, 1);
    assert_eq!(eval.rating, 50.0); // Neutral baseline when no active domains

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_ca_rating_dynamic_delta_narrowing() {
    let temp_dir =
        std::env::temp_dir().join(format!("randbotd_test_ca_delta_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let db = Database::open(&temp_dir).unwrap();

    let (ca_decl, ca_keypair) = create_test_ca("Delta Scaling CA");
    let ca_id = db.insert_ca(ca_decl.clone()).unwrap();

    let chain = create_leaf_chain(
        &ca_decl,
        &ca_keypair,
        "delta.randbot.hns",
        vec!["delta.randbot.hns".into()],
    );
    db.insert_cert_chain(chain).unwrap();

    // With 0 votes, delta is 50.0%
    let eval0 = db.evaluate_ca_rating(&ca_id, None).unwrap();
    assert_eq!(eval0.delta, 50.0);

    // Cast votes to narrow delta
    let phonebook = RwLock::new(Phonebook::new());
    for i in 1..=5 {
        let sk = SigningKey::from_bytes(&[i as u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        phonebook.write().unwrap().update_peer_ponderation(&pk, 60);
        cast_vote_helper(
            &db,
            "delta.randbot.hns",
            VoteAction::Tw,
            &sk,
            1700000000 + i as u64,
        );
    }

    let eval5 = db.evaluate_ca_rating(&ca_id, Some(&phonebook)).unwrap();
    assert!(eval5.delta < eval0.delta);
    assert_eq!(eval5.total_ca_votes, 5);

    let _ = std::fs::remove_dir_all(&temp_dir);
}
