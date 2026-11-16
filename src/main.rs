use bountyguard::scan_file_for_traps;
use std::{env, fs, path::Path, process};

fn walk(root: &Path, cur: &Path, alerts: &mut Vec<bountyguard::TrapAlert>) {
    let Ok(entries) = fs::read_dir(cur) else { return };
    for entry in entries.flatten() {
        let p = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if name == ".git" || name == "node_modules" || name == "target" {
            continue;
        }
        if p.is_dir() {
            walk(root, &p, alerts);
        } else if let Ok(txt) = fs::read_to_string(&p) {
            let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().to_string();
            alerts.extend(scan_file_for_traps(&rel, &txt));
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 || args[1] != "scan-dir" {
        eprintln!("Usage: bountyguard scan-dir <repository-path>");
        process::exit(2);
    }
    let root = Path::new(&args[2]);
    let mut alerts = Vec::new();
    walk(root, root, &mut alerts);
    if alerts.is_empty() {
        println!("CLEAN: No build-hook exfiltration traps detected in {}", root.display());
    } else {
        for a in &alerts {
            println!("ALERT: {}:{} -> {}", a.file, a.line, a.reason);
        }
        process::exit(1);
    }
}
