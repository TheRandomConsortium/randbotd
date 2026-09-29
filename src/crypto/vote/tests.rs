use super::*;

#[test]
fn test_vote_action_display_and_parse() {
    assert_eq!(VoteAction::Tw.as_str(), "TW");
    assert_eq!(VoteAction::Utw.as_str(), "UTW");
    assert!(VoteAction::Tw.is_tw());
    assert!(!VoteAction::Tw.is_utw());
    assert!(VoteAction::Utw.is_utw());
    assert!(!VoteAction::Utw.is_tw());

    assert_eq!(VoteAction::from_str_loose("tw").unwrap(), VoteAction::Tw);
    assert_eq!(VoteAction::from_str_loose("TW").unwrap(), VoteAction::Tw);
    assert_eq!(
        VoteAction::from_str_loose("trustworthy").unwrap(),
        VoteAction::Tw
    );
    assert_eq!(VoteAction::from_str_loose("utw").unwrap(), VoteAction::Utw);
    assert_eq!(VoteAction::from_str_loose("UTW").unwrap(), VoteAction::Utw);
    assert_eq!(
        VoteAction::from_str_loose("untrustworthy").unwrap(),
        VoteAction::Utw
    );
    assert!(VoteAction::from_str_loose("invalid").is_err());
}

#[test]
fn test_calculate_vote_difficulty_scaling_and_penalty() {
    // 0 active votes, 0 revisions: base 12
    assert_eq!(calculate_vote_difficulty(0, 0), 12);
    // 1 active vote, 0 revisions: 12 + 2*1 = 14
    assert_eq!(calculate_vote_difficulty(1, 0), 14);
    // 3 active votes, 0 revisions: 12 + 2*2 = 16
    assert_eq!(calculate_vote_difficulty(3, 0), 16);
    // 7 active votes, 0 revisions: 12 + 2*3 = 18
    assert_eq!(calculate_vote_difficulty(7, 0), 18);

    // 0 active votes, 1 revision: 12 + 2*0 + 2*1 = 14
    assert_eq!(calculate_vote_difficulty(0, 1), 14);
    // 1 active vote, 1 revision (flip on domain): 12 + 2*1 + 2*1 = 16
    assert_eq!(calculate_vote_difficulty(1, 1), 16);
    // 1 active vote, 2 revisions: logarithmic penalty stays 2: 12 + 2*1 + 2*1 = 16
    assert_eq!(calculate_vote_difficulty(1, 2), 16);
    // 1 active vote, 3 revisions: logarithmic penalty becomes 4: 12 + 2*1 + 2*2 = 18
    assert_eq!(calculate_vote_difficulty(1, 3), 18);
    // 1 active vote, 7 revisions: logarithmic penalty becomes 6: 12 + 2*1 + 2*3 = 20
    assert_eq!(calculate_vote_difficulty(1, 7), 20);
}

#[test]
fn test_vote_record_difficulty_cap_rejection() {
    let key_bytes = [0x5au8; 32];
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Both active votes and revisions at max push difficulty to 260 >= 256
    let diff = calculate_vote_difficulty(usize::MAX / 2, usize::MAX / 2);
    assert!(diff >= 256);

    let err = VoteRecord::new_signed(
        &signing_key,
        "cooling-off.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        usize::MAX / 2,
        usize::MAX / 2,
    )
    .unwrap_err();

    assert!(err.contains("exceeds maximum computable limit"));
    assert!(err.contains("cool down"));
}

#[test]
fn test_vote_record_build_and_validate_chain_continuity() {
    let key_bytes = [0x5au8; 32];
    let signing_key = SigningKey::from_bytes(&key_bytes);
    let pubkey = signing_key.verifying_key().to_bytes();

    // Vote 1: first vote on domain1 (seq 1, prev_hash 0)
    let vote1 = VoteRecord::new_signed(
        &signing_key,
        "first-domain.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .expect("vote1 should build");

    assert_eq!(vote1.vote_seq, 1);
    assert_eq!(vote1.prev_vote_hash, [0u8; 32]);
    assert_eq!(vote1.action, VoteAction::Tw);
    assert!(vote1.verify_pow());
    assert!(vote1.verify_signature(&pubkey).is_ok());
    assert!(vote1.validate_against_chain(None, 0, 0).is_ok());

    // Vote 2: second vote on domain2 (seq 2, chained from vote1)
    let vote2 = VoteRecord::new_signed(
        &signing_key,
        "second-domain.rand",
        VoteAction::Utw,
        2,
        vote1.vote_id,
        1050,
        1, // 1 active vote before this
        0, // 0 revisions on domain2
    )
    .expect("vote2 should build");

    assert_eq!(vote2.vote_seq, 2);
    assert_eq!(vote2.prev_vote_hash, vote1.vote_id);
    assert!(vote2.validate_against_chain(Some(&vote1), 1, 0).is_ok());

    // Vote 3: flip vote on domain1 from TW to UTW (seq 3, chained from vote2)
    let vote3 = VoteRecord::new_signed(
        &signing_key,
        "first-domain.rand",
        VoteAction::Utw,
        3,
        vote2.vote_id,
        1100,
        2, // 2 active votes before this
        1, // 1 revision on first-domain.rand before this
    )
    .expect("vote3 should build");

    assert_eq!(vote3.vote_seq, 3);
    assert_eq!(vote3.prev_vote_hash, vote2.vote_id);
    assert_eq!(vote3.revisions_on_domain, 1);
    assert!(vote3.validate_against_chain(Some(&vote2), 2, 1).is_ok());
}

#[test]
fn test_vote_record_discontinuous_sequence_rejection() {
    let signing_key = SigningKey::from_bytes(&[0x6bu8; 32]);

    let vote1 = VoteRecord::new_signed(
        &signing_key,
        "alpha.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    // Trying to skip seq 2 to seq 3 must fail validation
    let vote3_discontinuous = VoteRecord::new_signed(
        &signing_key,
        "beta.rand",
        VoteAction::Tw,
        3,
        vote1.vote_id,
        1010,
        1,
        0,
    )
    .unwrap();

    let err = vote3_discontinuous
        .validate_against_chain(Some(&vote1), 1, 0)
        .unwrap_err();
    assert!(err.contains("sequence discontinuity"));

    // First vote with seq != 1 must fail
    let err_first = vote3_discontinuous
        .validate_against_chain(None, 0, 0)
        .unwrap_err();
    assert!(err_first.contains("First vote for originator must have vote_seq = 1"));
}

#[test]
fn test_vote_record_broken_hash_link_rejection() {
    let signing_key = SigningKey::from_bytes(&[0x7cu8; 32]);

    let vote1 = VoteRecord::new_signed(
        &signing_key,
        "alpha.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    let vote2_broken_link = VoteRecord::new_signed(
        &signing_key,
        "beta.rand",
        VoteAction::Tw,
        2,
        [0x99u8; 32], // Wrong previous hash
        1010,
        1,
        0,
    )
    .unwrap();

    let err = vote2_broken_link
        .validate_against_chain(Some(&vote1), 1, 0)
        .unwrap_err();
    assert!(err.contains("Broken vote hash link"));
}

#[test]
fn test_vote_record_tampered_signature_or_challenge_rejection() {
    let signing_key = SigningKey::from_bytes(&[0x8du8; 32]);
    let attacker_key = SigningKey::from_bytes(&[0x9eu8; 32]);

    let mut vote = VoteRecord::new_signed(
        &signing_key,
        "target.rand",
        VoteAction::Tw,
        1,
        [0u8; 32],
        1000,
        0,
        0,
    )
    .unwrap();

    // Verify signature with attacker pubkey fails
    let attacker_pubkey = attacker_key.verifying_key().to_bytes();
    assert!(vote.verify_signature(&attacker_pubkey).is_err());

    // Tampering with vote action breaks signature and challenge
    vote.action = VoteAction::Utw;
    assert!(vote.validate_against_chain(None, 0, 0).is_err());
}
