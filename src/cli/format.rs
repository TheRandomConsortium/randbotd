use serde_json::Value;

pub fn print_status(json_str: &str, as_json: bool) {
    if as_json {
        println!("{}", json_str);
        return;
    }
    if let Ok(val) = serde_json::from_str::<Value>(json_str) {
        println!("\n🤖 randbotd Node Status");
        println!("==================================================");
        println!(
            "  Identity Pubkey:   {}",
            val["node_pubkey_hex"].as_str().unwrap_or("-")
        );
        println!(
            "  Daemon State:      {}",
            val["status"].as_str().unwrap_or("unknown").to_uppercase()
        );
        println!("  Connected Peers:   {}", val["peer_count"]);
        println!("--------------------------------------------------");
        println!("  Registered CAs:    {}", val["total_cas"]);
        println!("  Active Offers:     {}", val["total_offers"]);
        println!("  Issued Certs:      {}", val["total_certs"]);
        println!("  Active CRLs:       {}", val["total_crls"]);
        println!("  Domain Purges:     {}", val["total_purges"]);
        println!("==================================================\n");
    } else {
        println!("{}", json_str);
    }
}

pub fn print_cas(json_str: &str, as_json: bool) {
    if as_json {
        println!("{}", json_str);
        return;
    }
    if let Ok(Value::Array(cas)) = serde_json::from_str::<Value>(json_str) {
        if cas.is_empty() {
            println!("No CAs registered in local database.");
            return;
        }
        println!("\n🔑 Registered Certificate Authorities ({})", cas.len());
        println!("┌──────────────────────────────────────────────────┬─────────────────────────────┬──────────────┬────────┐");
        println!("│ CA ID                                            │ Common Name                 │ Type         │ Status │");
        println!("├──────────────────────────────────────────────────┼─────────────────────────────┼──────────────┼────────┤");
        for ca in cas {
            let ca_id = ca["ca_id_hex"].as_str().unwrap_or("-");
            let cn = ca["subject"]["common_name"].as_str().unwrap_or("-");
            let is_intermediate = ca["is_intermediate"].as_bool().unwrap_or(false);
            let ca_type = if is_intermediate {
                "Intermediate"
            } else {
                "Root CA"
            };
            let is_draft = ca["is_draft"].as_bool().unwrap_or(false);
            let status = if is_draft { "Draft" } else { "Active" };
            println!(
                "│ {:<48} │ {:<27} │ {:<12} │ {:<6} │",
                ca_id,
                truncate(cn, 27),
                ca_type,
                status
            );
        }
        println!("└──────────────────────────────────────────────────┴─────────────────────────────┴──────────────┴────────┘\n");
    } else {
        println!("{}", json_str);
    }
}

pub fn print_offers(json_str: &str, as_json: bool) {
    if as_json {
        println!("{}", json_str);
        return;
    }
    if let Ok(Value::Array(offers)) = serde_json::from_str::<Value>(json_str) {
        if offers.is_empty() {
            println!("No certificate offers found.");
            return;
        }
        println!("\n📜 Certificate Offer Catalog ({})", offers.len());
        println!("┌──────┬──────────────────────────────┬──────────────┬──────────────┬────────┐");
        println!("│ ID   │ Profile Name                 │ Algorithm    │ TTL (Days)   │ Draft  │");
        println!("├──────┼──────────────────────────────┼──────────────┼──────────────┼────────┤");
        for o in offers {
            let id = o["offer_id"].as_u64().unwrap_or(0);
            let name = o["name"].as_str().unwrap_or("-");
            let alg = o["key_algorithm"].as_str().unwrap_or("-");
            let ttl_days = o["ttl_seconds"].as_u64().unwrap_or(0) / 86400;
            let is_draft = o["is_draft"].as_bool().unwrap_or(false);
            println!(
                "│ {:<4} │ {:<28} │ {:<12} │ {:<12} │ {:<6} │",
                id,
                truncate(name, 28),
                alg,
                ttl_days,
                is_draft
            );
        }
        println!(
            "└──────┴──────────────────────────────┴──────────────┴──────────────┴────────┘\n"
        );
    } else {
        println!("{}", json_str);
    }
}

pub fn print_peers(json_str: &str, as_json: bool) {
    if as_json {
        println!("{}", json_str);
        return;
    }
    if let Ok(Value::Array(peers)) = serde_json::from_str::<Value>(json_str) {
        if peers.is_empty() {
            println!("No known peers in phonebook.");
            return;
        }
        println!("\n🌐 Known P2P Network Peers ({})", peers.len());
        println!("┌─────────────────────────────┬──────────────────────────────────────────────────┬──────┐");
        println!("│ Address                     │ Peer Pubkey                                      │ Seed │");
        println!("├─────────────────────────────┼──────────────────────────────────────────────────┼──────┤");
        for p in peers {
            let addr = p["address"].as_str().unwrap_or("-");
            let pubkey = p["pubkey_hex"].as_str().unwrap_or("-");
            let is_seed = p["verified_seed"]
                .as_bool()
                .or_else(|| p["self_declared_seed"].as_bool())
                .unwrap_or(false);
            println!(
                "│ {:<27} │ {:<48} │ {:<4} │",
                truncate(addr, 27),
                truncate(pubkey, 48),
                if is_seed { "Yes" } else { "No" }
            );
        }
        println!("└─────────────────────────────┴──────────────────────────────────────────────────┴──────┘\n");
    } else {
        println!("{}", json_str);
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
