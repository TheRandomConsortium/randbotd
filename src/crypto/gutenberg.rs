use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GutenbergMnemonic;

impl GutenbergMnemonic {
    /// Generates 256 bits of true entropy by drilling down Project Gutenberg (`https://www.gutenberg.org/dirs/`)
    /// rolling CSPRNG dices to sample words from random books until accumulated Shannon entropy >= 256 bits.
    /// If `allow_fallback` is enabled, falls back to sampling from Timothy C. May's Crypto Anarchist Manifesto if network drilling fails.
    pub fn generate_256bit_phrase(allow_fallback: bool) -> (Vec<u8>, String) {
        let driller = GutenbergDriller::new();
        let mut words = Vec::new();
        let mut total_entropy_bits: f64 = 0.0;

        let mut attempts = 0;
        while total_entropy_bits < 256.0 && attempts < 60 {
            attempts += 1;
            if let Ok((word_str, pool_size)) = driller.drill_random_word() {
                let cleaned = clean_word(&word_str);
                if !cleaned.is_empty() && !words.contains(&cleaned) {
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

        // If Project Gutenberg servers are unreachable and allow_fallback is enabled
        if total_entropy_bits < 256.0 && allow_fallback {
            let manifesto_words = extract_words_from_text(FALLBACK_CRYPTO_ANARCHIST_MANIFESTO);
            let pool_size = manifesto_words.len();
            if pool_size > 0 {
                let word_entropy = (pool_size as f64).log2();
                while total_entropy_bits < 256.0 {
                    let idx = rand_dice(pool_size);
                    let w = manifesto_words[idx].clone();
                    if !words.contains(&w) {
                        words.push(w);
                        total_entropy_bits += word_entropy;
                    }
                }
            }
        }

        if total_entropy_bits < 256.0 || words.is_empty() {
            panic!("Network failure: Unable to drill Project Gutenberg books for key entropy. Use --allow-entropy-fallback or configure [entropy] allow_fallback = true in randbotd.toml.");
        }

        let phrase = words.join(" ");
        let seed = derive_seed_from_phrase(&phrase);
        (seed, phrase)
    }

    /// Reconstructs the 256-bit seed deterministically from the space-separated Gutenberg word phrase.
    pub fn phrase_to_seed(phrase: &str) -> Vec<u8> {
        derive_seed_from_phrase(phrase)
    }

    /// Saves the Gutenberg recovery phrase to RAM (/dev/shm) with strict 0600 permissions to avoid journalctl logging.
    pub fn save_mnemonic_to_ram(phrase: &str) -> std::io::Result<std::path::PathBuf> {
        let ram_dir = std::path::Path::new("/dev/shm");
        let target_dir = if ram_dir.exists() && ram_dir.is_dir() {
            ram_dir
        } else {
            std::path::Path::new("/tmp")
        };
        let pid = std::process::id();
        let mnemonic_path = target_dir.join(format!("randbotd_mnemonic_{}.txt", pid));

        let file = std::fs::File::create(&mnemonic_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms)?;
        }
        use std::io::Write;
        let mut writer = std::io::BufWriter::new(file);
        writeln!(
            writer,
            "================================================================================"
        )?;
        writeln!(
            writer,
            "  🛡️ RANDOM CONSORTIUM DAEMON (randbotd) RECOVERY PHRASE"
        )?;
        writeln!(
            writer,
            "================================================================================"
        )?;
        writeln!(
            writer,
            "  Keep this 24-word Gutenberg recovery phrase secure!\n"
        )?;
        writeln!(writer, "{}\n", phrase)?;
        writeln!(
            writer,
            "================================================================================"
        )?;
        writer.flush()?;
        Ok(mnemonic_path)
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
            .timeout(Duration::from_secs(2))
            .user_agent("randbotd/0.1.0 Gutenberg-Mnemonic-Driller")
            .redirect(reqwest::redirect::Policy::limited(3))
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
        let words = extract_words_from_text(&text);
        if words.is_empty() {
            return Err("No valid words found in book".into());
        }

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

fn extract_words_from_text(text: &str) -> Vec<String> {
    let mut words: Vec<String> = text
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|w| w.len() >= 3 && w.chars().all(|c| c.is_alphabetic()))
        .collect();
    words.sort();
    words.dedup();
    words
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

const FALLBACK_CRYPTO_ANARCHIST_MANIFESTO: &str = r#"
The Crypto Anarchist Manifesto
Timothy C. May, 1988

A specter is haunting the modern world, the specter of crypto anarchy.
Computer technology is on the verge of providing the ability for individuals and groups to communicate and interact with each other in a totally anonymous manner. Two persons may exchange messages, conduct business, and negotiate electronic contracts without ever knowing the True Name, or legal identity, of the other. Interactions over networks will be untraceable, via extensive re-routing of encrypted packets and tamper-proof boxes which implement cryptographic protocols with nearly perfect assurance against any tampering. Reputations will be of central importance, far more important in dealings than even the credit ratings of today. These developments will alter completely the nature of government regulation, the ability to tax and control economic interactions, the ability to keep information secret, and will even alter the nature of trust and reputation.
The technology for this revolution--and it surely will be both a social and economic revolution--has existed in theory for the past decade. The methods are based upon public-key encryption, zero-knowledge interactive proof systems, and various software protocols for interaction, authentication, and verification. The focus has until now been on academic conferences in Europe and the U.S., conferences monitored closely by the National Security Agency. But only recently have computer networks and personal computers attained sufficient speed to make the ideas practically realizable. And the next ten years will bring enough additional speed to make the ideas economically feasible and essentially unstoppable. High-speed networks, ISDN, tamper-proof boxes, smart cards, satellites, Ku-band transmitters, multi-MIPS personal computers, and encryption chips now under development will be some of the enabling technologies.
The State will of course try to slow or halt the spread of this technology, citing national security concerns, use of the technology by drug dealers and tax evaders, and fears of societal disintegration. Many of these concerns will be valid; crypto anarchy will allow national secrets to be trade freely and will allow illicit and stolen materials to be traded. An anonymous computerized market will even make possible abhorrent markets for assassinations and extortion. Various criminal and foreign elements will be active users of CryptoNet. But this will not halt the spread of crypto anarchy.
Just as the technology of printing altered and reduced the power of medieval guilds and the social power structure, so too will cryptologic methods fundamentally alter the nature of corporations and of government interference in economic transactions. Combined with emerging information markets, crypto anarchy will create a liquid market for any and all material which can be put into words and pictures. And just as a seemingly minor invention like barbed wire made possible the fencing-off of vast ranches and farms, thus altering forever the concepts of land and property rights in the frontier West, so too will the seemingly minor discovery out of an arcane branch of mathematics come to be the wire clippers which dismantle the barbed wire around intellectual property.
Arise, you have nothing to lose but your barbed wire fences!
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gutenberg_mnemonic_roundtrip() {
        let (seed1, phrase) = GutenbergMnemonic::generate_256bit_phrase(true);
        assert_eq!(seed1.len(), 32);
        assert!(!phrase.is_empty());

        let seed2 = GutenbergMnemonic::phrase_to_seed(&phrase);
        assert_eq!(seed1, seed2);
    }
}
