//! CA Rating Propagation Engine & Bi-Directional Image Cleaning (REP-05 / REP-06)
//!
//! Provides on-demand, real-time evaluation of a CA's public reputation rating as the
//! weighted average of trust scores of all issued domains, dynamic CA Delta tolerance
//! windows, and immediate image cleaning via domain purges.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::vote::lazy::{calculate_dynamic_delta, DomainTrustEvaluation};
use crate::net::phonebook::Phonebook;
use crate::storage::db::ca_subtable::bytes32_to_hex;
use crate::storage::db::Database;

/// Comprehensive CA public reputation evaluation result (REP-05)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaRatingEvaluation {
    /// 32-byte deterministic CA identifier
    pub ca_id: [u8; 32],
    /// Hexadecimal string representation of ca_id
    pub ca_id_hex: String,
    /// Common Name (CN) of the CA
    pub common_name: String,
    /// Aggregated public rating in [0.0, 100.0] (50.0 is neutral baseline per ACME-02)
    pub rating: f64,
    /// Dynamic tolerance window (+/- Delta %) in [0.0, 50.0]
    pub delta: f64,
    /// Lower confidence bound: max(0.0, rating - delta)
    pub lower_bound: f64,
    /// Upper confidence bound: min(100.0, rating + delta)
    pub upper_bound: f64,
    /// Total issued domain names discovered across certificate chains
    pub total_issued_domains: usize,
    /// Number of active domains included in the rating calculation
    pub active_domains_count: usize,
    /// Number of domains excluded due to active CA purges (REP-06 / CA-07)
    pub purged_domains_count: usize,
    /// Number of domains excluded due to CRL revocations
    pub revoked_domains_count: usize,
    /// Total active votes cast across all active domains of this CA
    pub total_ca_votes: usize,
    /// Total weighted voter ponderation sum across all active domains of this CA
    pub total_ca_weight: f64,
    /// Active network nodes count used for dynamic Delta rescaling
    pub network_active_nodes: usize,
    /// Detailed evaluations for each active domain
    pub domain_evaluations: Vec<DomainTrustEvaluation>,
    /// Unix timestamp when this evaluation was computed
    pub evaluated_at: u64,
}

impl Database {
    /// Evaluates the public reputation rating of a CA on-demand in real-time (REP-05)
    pub fn evaluate_ca_rating(
        &self,
        ca_id: &[u8; 32],
        phonebook: Option<&RwLock<Phonebook>>,
    ) -> Result<CaRatingEvaluation, String> {
        let ca = self
            .get_ca(ca_id)
            .ok_or_else(|| format!("CA declaration {:02x?} not found", &ca_id[..4]))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Retrieve all purges for this CA and index actively purged domains and serials
        let purges = self.get_purges_for_ca(ca_id);
        let mut active_purged_domains = HashSet::new();
        let mut active_purged_serials = HashSet::new();
        for p in &purges {
            if p.expires_at > now {
                active_purged_domains.insert(p.domain.trim().to_ascii_lowercase());
                if let Some(ref s) = p.serial_number {
                    active_purged_serials.insert(s.clone());
                }
            }
        }

        // 2. Discover all certificate chains issued by or associated with this CA
        let all_chains = self.list_cert_chains();
        let ca_hex = bytes32_to_hex(ca_id);
        let mut discovered_domains = HashSet::new();
        let mut purged_domains = HashSet::new();
        let mut revoked_domains = HashSet::new();
        let mut active_domains = HashSet::new();

        for chain in &all_chains {
            let matches_issuer = chain.target_certificate.issuer.common_name
                == ca.subject.common_name
                || chain
                    .root_certificate
                    .as_ref()
                    .is_some_and(|r| r.subject.common_name == ca.subject.common_name)
                || chain
                    .intermediate_certificates
                    .iter()
                    .any(|i| i.subject.common_name == ca.subject.common_name)
                || chain.target_certificate.pem_certificate.contains(&ca_hex);

            if !matches_issuer {
                continue;
            }

            let leaf = &chain.target_certificate;
            let mut chain_domains = Vec::new();
            let cn_clean = leaf.subject.common_name.trim().to_ascii_lowercase();
            if !cn_clean.is_empty() && cn_clean != ca.subject.common_name.to_ascii_lowercase() {
                chain_domains.push(cn_clean);
            }
            for san in &leaf.sans {
                let san_clean = san.trim().to_ascii_lowercase();
                if !san_clean.is_empty() && !chain_domains.contains(&san_clean) {
                    chain_domains.push(san_clean);
                }
            }

            let is_revoked = self.is_serial_revoked(ca_id, &leaf.serial_number)
                || self.is_cert_revoked_any(&leaf.serial_number);
            let is_purged = active_purged_serials.contains(&leaf.serial_number);

            for dom in chain_domains {
                discovered_domains.insert(dom.clone());
                if is_revoked {
                    revoked_domains.insert(dom.clone());
                } else if is_purged || active_purged_domains.contains(&dom) {
                    purged_domains.insert(dom.clone());
                } else {
                    active_domains.insert(dom);
                }
            }
        }

        // Also incorporate any unexpired domain purges declared for this CA even without active chains
        for p in &active_purged_domains {
            discovered_domains.insert(p.clone());
            purged_domains.insert(p.clone());
            active_domains.remove(p);
        }

        // Exclude purged and revoked domains from active set
        for p in &purged_domains {
            active_domains.remove(p);
        }
        for r in &revoked_domains {
            // Only keep in active if not purged and not all certs are revoked
            if !active_purged_domains.contains(r) {
                // If every chain for this domain was revoked, ensure removed
                active_domains.remove(r);
            }
        }

        // 3. For each active domain, evaluate trust score lazily via REP-04
        let mut domain_evaluations = Vec::new();
        let mut total_ca_votes = 0usize;
        let mut total_ca_weight = 0.0f64;
        let mut weighted_score_sum = 0.0f64;

        let mut sorted_domains: Vec<String> = active_domains.into_iter().collect();
        sorted_domains.sort();

        let network_active_nodes = match phonebook {
            Some(pb_lock) => pb_lock.read().map(|p| p.peers.len().max(1)).unwrap_or(1),
            None => {
                let all_votes = self.list_all_votes();
                let mut voters = HashSet::new();
                for v in &all_votes {
                    voters.insert(v.voter_pubkey);
                }
                voters.len().max(1)
            }
        };

        for dom in &sorted_domains {
            let eval = self.evaluate_domain_trust(dom, phonebook);
            let weight = eval.total_voter_weight;
            total_ca_votes += eval.total_active_votes;
            total_ca_weight += weight;
            weighted_score_sum += eval.trust_score * weight;
            domain_evaluations.push(eval);
        }

        // 4. Calculate CA rating: weighted average or neutral baseline (50.0%)
        let rating = if total_ca_weight > 0.0 {
            ((weighted_score_sum / total_ca_weight) * 100.0).round() / 100.0
        } else if domain_evaluations.is_empty() || total_ca_votes == 0 {
            50.0
        } else {
            let sum: f64 = domain_evaluations.iter().map(|e| e.trust_score).sum();
            ((sum / domain_evaluations.len() as f64) * 100.0).round() / 100.0
        };

        // 5. Calculate CA dynamic delta and confidence window
        let delta = calculate_dynamic_delta(total_ca_votes, network_active_nodes);
        let lower_bound = ((rating - delta).max(0.0) * 100.0).round() / 100.0;
        let upper_bound = ((rating + delta).min(100.0) * 100.0).round() / 100.0;

        Ok(CaRatingEvaluation {
            ca_id: *ca_id,
            ca_id_hex: bytes32_to_hex(ca_id),
            common_name: ca.subject.common_name,
            rating,
            delta,
            lower_bound,
            upper_bound,
            total_issued_domains: discovered_domains.len(),
            active_domains_count: sorted_domains.len(),
            purged_domains_count: purged_domains.len(),
            revoked_domains_count: revoked_domains.len(),
            total_ca_votes,
            total_ca_weight,
            network_active_nodes,
            domain_evaluations,
            evaluated_at: now,
        })
    }
}

#[cfg(test)]
mod tests;
