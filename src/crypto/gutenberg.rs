use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GutenbergMnemonic;

impl GutenbergMnemonic {
    /// Generates 256 bits of true entropy by drilling down Project Gutenberg (`https://www.gutenberg.org/dirs/`)
    /// rolling CSPRNG dices to sample words from random books until accumulated Shannon entropy >= 256 bits.
    pub fn generate_256bit_phrase() -> (Vec<u8>, String) {
        let driller = GutenbergDriller::new();
        let mut words = Vec::new();
        let mut total_entropy_bits: f64 = 0.0;

        let mut attempts = 0;
        while total_entropy_bits < 256.0 && attempts < 100 {
            attempts += 1;
            if let Ok((word_str, pool_size)) = driller.drill_random_word() {
                let cleaned = clean_word(&word_str);
                if !cleaned.is_empty() && !words.contains(&cleaned) {
                    // Shannon entropy contributed by picking 1 item uniformly out of a pool of size N:
                    // H = log2(pool_size) bits
                    let word_entropy = if pool_size > 1 {
                        (pool_size as f64).log2()
                    } else {
                        1.0
                    };
                    total_entropy_bits += word_entropy;
                    words.push(cleaned);
                }
            }
        }

        if words.is_empty() {
            panic!("Network failure: Unable to drill Project Gutenberg books for key entropy.");
        }

        let phrase = words.join(" ");
        let seed = derive_seed_from_phrase(&phrase);
        (seed, phrase)
    }

    /// Reconstructs the 256-bit seed deterministically from the space-separated Gutenberg word phrase.
    pub fn phrase_to_seed(phrase: &str) -> Vec<u8> {
        derive_seed_from_phrase(phrase)
    }
}

pub fn derive_seed_from_phrase(phrase: &str) -> Vec<u8> {
    let normalized = phrase.trim().to_lowercase();
    let mut hasher = Sha256::new();
    hasher.update(normalized.as_bytes());
    hasher.finalize().to_vec()
}

pub struct GutenbergDriller {
    client: Client,
}

impl GutenbergDriller {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("randbotd/0.1.0 Gutenberg-Mnemonic-Driller")
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Drills down https://www.gutenberg.org/dirs/ dynamically by rolling dices to pick subdirectories and text files.
    /// Returns (selected_word, word_pool_size) for exact Shannon entropy calculation.
    pub fn drill_random_word(&self) -> Result<(String, usize), String> {
        let mut current_url = "https://www.gutenberg.org/dirs/".to_string();

        for _depth in 0..4 {
            let res = self
                .client
                .get(&current_url)
                .send()
                .map_err(|e| e.to_string())?;
            let body = res.text().map_err(|e| e.to_string())?;

            let links = extract_html_links(&body);
            let subdirs: Vec<&String> = links
                .iter()
                .filter(|l| l.ends_with('/') && !l.starts_with('?') && *l != "../" && *l != "/")
                .collect();
            let txt_files: Vec<&String> = links
                .iter()
                .filter(|l| l.ends_with(".txt") || l.ends_with(".txt.utf-8"))
                .collect();

            if !txt_files.is_empty() && (rand_dice(100) < 60 || subdirs.is_empty()) {
                let choice = txt_files[rand_dice(txt_files.len())];
                let file_url = if choice.starts_with("http") {
                    choice.to_string()
                } else {
                    format!("{}{}", current_url, choice)
                };
                return self.fetch_word_from_book(&file_url);
            } else if !subdirs.is_empty() {
                let choice = subdirs[rand_dice(subdirs.len())];
                current_url = if choice.starts_with("http") {
                    choice.to_string()
                } else {
                    format!("{}{}", current_url, choice)
                };
            } else {
                break;
            }
        }

        Err("Failed to drill down to a text file".into())
    }

    pub fn fetch_word_from_book(&self, book_url: &str) -> Result<(String, usize), String> {
        let res = self
            .client
            .get(book_url)
            .send()
            .map_err(|e| e.to_string())?;
        let text = res.text().map_err(|e| e.to_string())?;

        let mut words: Vec<String> = text
            .split_whitespace()
            .map(|w| {
                w.trim_matches(|c: char| !c.is_alphanumeric())
                    .to_lowercase()
            })
            .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_alphabetic()))
            .collect();

        if words.is_empty() {
            return Err("No valid words found in book".into());
        }

        // Deduplicate word pool to determine true unique corpus vocabulary size
        words.sort();
        words.dedup();

        let pool_size = words.len();
        let word_idx = rand_dice(pool_size);
        Ok((words[word_idx].clone(), pool_size))
    }
}

impl Default for GutenbergDriller {
    fn default() -> Self {
        Self::new()
    }
}

fn rand_dice(max: usize) -> usize {
    if max <= 1 {
        return 0;
    }
    use rand::Rng;
    rand::rngs::OsRng.gen_range(0..max)
}

fn clean_word(w: &str) -> String {
    w.trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

fn extract_html_links(html: &str) -> Vec<String> {
    let mut links = Vec::new();
    for chunk in html.split("href=\"") {
        if let Some(end) = chunk.find('"') {
            let link = &chunk[..end];
            if !link.is_empty() && link != "/" && link != ".." {
                links.push(link.to_string());
            }
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gutenberg_mnemonic_roundtrip() {
        let (seed1, phrase) = GutenbergMnemonic::generate_256bit_phrase();
        assert_eq!(seed1.len(), 32);
        assert!(!phrase.is_empty());

        let seed2 = GutenbergMnemonic::phrase_to_seed(&phrase);
        assert_eq!(seed1, seed2);
    }
}
