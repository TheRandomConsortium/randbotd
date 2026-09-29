use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::identity::NodeIdentity;
use crate::crypto::vote::{VoteAction, VoteRecord};
use crate::net::ipc::{IpcCommand, IpcResponse};
use crate::pki::purge::validate_domain_name;
use crate::storage::db::ca_subtable::{bytes32_to_hex, hex_to_bytes32};
use crate::storage::db::Database;

use super::{IpcContext, IpcHandler};

/// IPC Handler for dynamic domain reputation voting (REP-02)
pub struct VoteHandler;

impl IpcHandler for VoteHandler {
    fn handle(&self, command: &IpcCommand, ctx: &IpcContext) -> Option<IpcResponse> {
        match command {
            IpcCommand::CastVote { domain, action } => {
                Some(Self::handle_cast_vote(domain, action, ctx.db, ctx.identity))
            }
            IpcCommand::GetVote { domain } => {
                Some(Self::handle_get_vote(domain, ctx.db, ctx.identity))
            }
            IpcCommand::ListVotes {
                domain,
                voter_hex,
                my_votes_only,
            } => Some(Self::handle_list_votes(
                domain.as_deref(),
                voter_hex.as_deref(),
                *my_votes_only,
                ctx.db,
                ctx.identity,
            )),
            IpcCommand::BroadcastVote { vote_id_hex } => {
                Some(Self::handle_broadcast_vote(vote_id_hex, ctx.db))
            }
            _ => None,
        }
    }
}

impl VoteHandler {
    pub fn handle_cast_vote(
        domain: &str,
        action_str: &str,
        db: Option<&Arc<Database>>,
        identity: Option<&NodeIdentity>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let node_id = match identity {
            Some(id) => id,
            None => {
                return IpcResponse::Error {
                    reason: "Node identity is uninitialized".to_string(),
                }
            }
        };

        // Enforce: Headless nodes cannot vote since they aren't supposed to be navigating
        if node_id.is_headless() {
            return IpcResponse::Error {
                reason: "Headless nodes cannot cast consensus votes: node is running in headless mode with navigation disabled".to_string(),
            };
        }

        let clean_domain = domain.trim().to_ascii_lowercase();
        if let Err(e) = validate_domain_name(&clean_domain) {
            return IpcResponse::Error {
                reason: format!("Invalid domain name `{}`: {}", clean_domain, e),
            };
        }

        let action = match VoteAction::from_str_loose(action_str) {
            Ok(a) => a,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        let voter_pubkey = node_id.verifying_key().to_bytes();
        let (prev_vote, active_votes, revisions_on_domain) =
            database.get_vote_context(&voter_pubkey, &clean_domain);

        let vote_seq = prev_vote.as_ref().map(|p| p.vote_seq + 1).unwrap_or(1);
        let prev_vote_hash = prev_vote.as_ref().map(|p| p.vote_id).unwrap_or([0u8; 32]);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let difficulty =
            crate::crypto::vote::calculate_vote_difficulty(active_votes, revisions_on_domain);
        if difficulty > crate::crypto::vote::MAX_COMPUTABLE_DIFFICULTY {
            return IpcResponse::Error {
                reason: format!(
                    "Required vote difficulty ({}) exceeds maximum computable limit ({}) for SHA-256. Please vote on other domains you haven't flipped so much to allow your active voting difficulty to cool down.",
                    difficulty, crate::crypto::vote::MAX_COMPUTABLE_DIFFICULTY
                ),
            };
        }

        let vote = match VoteRecord::new_signed(
            node_id.signing_key(),
            &clean_domain,
            action,
            vote_seq,
            prev_vote_hash,
            timestamp,
            active_votes,
            revisions_on_domain,
        ) {
            Ok(v) => v,
            Err(e) => {
                return IpcResponse::Error {
                    reason: format!("Failed to create signed vote record: {}", e),
                }
            }
        };

        if let Err(e) = database.insert_vote(vote.clone()) {
            return IpcResponse::Error {
                reason: format!("Failed to persist vote to database: {}", e),
            };
        }

        match serde_json::to_string_pretty(&vote) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize vote: {}", e),
            },
        }
    }

    pub fn handle_get_vote(
        domain: &str,
        db: Option<&Arc<Database>>,
        identity: Option<&NodeIdentity>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let my_pubkey = identity.and_then(|id| {
            if id.is_voter() {
                Some(id.verifying_key().to_bytes())
            } else {
                None
            }
        });

        let status = database.get_domain_vote_status(my_pubkey.as_ref(), domain);

        match serde_json::to_string_pretty(&status) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize domain vote status: {}", e),
            },
        }
    }

    pub fn handle_list_votes(
        domain: Option<&str>,
        voter_hex: Option<&str>,
        my_votes_only: Option<bool>,
        db: Option<&Arc<Database>>,
        identity: Option<&NodeIdentity>,
    ) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let voter_pubkey = if my_votes_only == Some(true) {
            match identity {
                Some(id) => Some(id.verifying_key().to_bytes()),
                None => {
                    return IpcResponse::Error {
                        reason: "Local node identity is uninitialized".to_string(),
                    }
                }
            }
        } else if let Some(hex_str) = voter_hex {
            match hex_to_bytes32(hex_str) {
                Ok(pk) => Some(pk),
                Err(e) => return IpcResponse::Error { reason: e },
            }
        } else {
            None
        };

        let votes = database.list_active_domain_votes(domain, voter_pubkey.as_ref());

        match serde_json::to_string_pretty(&votes) {
            Ok(json_str) => IpcResponse::Ok { message: json_str },
            Err(e) => IpcResponse::Error {
                reason: format!("Failed to serialize votes: {}", e),
            },
        }
    }

    pub fn handle_broadcast_vote(vote_id_hex: &str, db: Option<&Arc<Database>>) -> IpcResponse {
        let database = match db {
            Some(d) => d,
            None => {
                return IpcResponse::Error {
                    reason: "Database is uninitialized".to_string(),
                }
            }
        };

        let vote_id = match hex_to_bytes32(vote_id_hex) {
            Ok(id) => id,
            Err(e) => return IpcResponse::Error { reason: e },
        };

        match database.get_vote(&vote_id) {
            Some(vote) => IpcResponse::Ok {
                message: format!(
                    "Vote #{} ({}) for `{}` [ID: {}] staged for P2P broadcast",
                    vote.vote_seq,
                    vote.action,
                    vote.domain,
                    bytes32_to_hex(&vote.vote_id)
                ),
            },
            None => IpcResponse::Error {
                reason: format!("Vote with ID `{}` not found in database", vote_id_hex),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::identity::NodeRole;
    use crate::net::phonebook::Phonebook;
    use std::sync::RwLock;

    #[test]
    fn test_ipc_cast_vote_and_get_vote_flow() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_vote_{}", rand::random::<u64>()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let identity = NodeIdentity::from_seed_and_role(&[0x45u8; 32], NodeRole::Voter);
        let ctx = IpcContext::new(&phonebook, Some(&db), Some(&identity));

        let handler = VoteHandler;

        // 1. Initial GetVote: has not voted
        let get_cmd = IpcCommand::GetVote {
            domain: "banana.rand".to_string(),
        };
        let resp = handler.handle(&get_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Ok { message } => {
                let status: crate::storage::db::subtables::vote_subtable::DomainVoteStatus =
                    serde_json::from_str(&message).unwrap();
                assert!(!status.has_voted);
                assert_eq!(status.total_active_votes, 0);
            }
            _ => panic!("Expected Ok response"),
        }

        // 2. Cast vote TW
        let cast_cmd = IpcCommand::CastVote {
            domain: "banana.rand".to_string(),
            action: "TW".to_string(),
        };
        let resp_cast = handler.handle(&cast_cmd, &ctx).unwrap();
        assert!(matches!(resp_cast, IpcResponse::Ok { .. }));

        // 3. GetVote after voting: has_voted = true
        let resp_after = handler.handle(&get_cmd, &ctx).unwrap();
        match resp_after {
            IpcResponse::Ok { message } => {
                let status: crate::storage::db::subtables::vote_subtable::DomainVoteStatus =
                    serde_json::from_str(&message).unwrap();
                assert!(status.has_voted);
                assert_eq!(status.my_vote.unwrap().action, VoteAction::Tw);
                assert_eq!(status.total_active_votes, 1);
                assert_eq!(status.tw_count, 1);
                assert_eq!(status.utw_count, 0);
            }
            _ => panic!("Expected Ok response"),
        }

        // 4. Flip vote to UTW
        let flip_cmd = IpcCommand::CastVote {
            domain: "banana.rand".to_string(),
            action: "UTW".to_string(),
        };
        let resp_flip = handler.handle(&flip_cmd, &ctx).unwrap();
        assert!(matches!(resp_flip, IpcResponse::Ok { .. }));

        // 5. GetVote after flip: has_voted = true, action = UTW, revisions = 2, total = 1
        let resp_after_flip = handler.handle(&get_cmd, &ctx).unwrap();
        match resp_after_flip {
            IpcResponse::Ok { message } => {
                let status: crate::storage::db::subtables::vote_subtable::DomainVoteStatus =
                    serde_json::from_str(&message).unwrap();
                assert!(status.has_voted);
                assert_eq!(status.my_vote.unwrap().action, VoteAction::Utw);
                assert_eq!(status.revisions_on_domain, 2);
                assert_eq!(status.total_active_votes, 1);
                assert_eq!(status.tw_count, 0);
                assert_eq!(status.utw_count, 1);
            }
            _ => panic!("Expected Ok response"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ipc_headless_node_cannot_vote() {
        let temp_dir =
            std::env::temp_dir().join(format!("randbotd_ipc_headless_{}", rand::random::<u64>()));
        let db = Arc::new(Database::open(&temp_dir).unwrap());
        let phonebook = Arc::new(RwLock::new(Phonebook::new()));
        let headless_id = NodeIdentity::from_seed_and_role(&[0x78u8; 32], NodeRole::Headless);
        let ctx = IpcContext::new(&phonebook, Some(&db), Some(&headless_id));

        let handler = VoteHandler;

        let cast_cmd = IpcCommand::CastVote {
            domain: "banana.rand".to_string(),
            action: "TW".to_string(),
        };
        let resp = handler.handle(&cast_cmd, &ctx).unwrap();
        match resp {
            IpcResponse::Error { reason } => {
                assert!(reason.contains("Headless nodes cannot cast consensus votes"));
            }
            _ => panic!("Expected Error response for headless node"),
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
