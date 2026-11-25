//! FableScope headless CLI — exposes the offline service layer for scripting,
//! CI, and automation without the desktop UI (Phase 4 "headless CLI sharing the
//! same service layer"). Each subcommand prints JSON to stdout.

use std::io::Read;
use std::process::ExitCode;

fn usage() -> &'static str {
    "FableScope CLI\n\
     usage: fablescope <command> [args]\n\n\
     commands:\n\
     \x20 hash-id <hash>              identify likely hash types\n\
     \x20 cvss <vector>              score a CVSS v3.1 vector\n\
     \x20 passwords <len> <count>    generate algorithmic passwords\n\
     \x20 passphrase <words>         generate a Diceware passphrase\n\
     \x20 mutate <word>              generate fuzz payloads for a seed\n\
     \x20 subdomains <root>          generate subdomain candidates\n\
     \x20 wordlist-sources           list built-in wordlist sources\n\
     \x20 import-adapters            list external-tool import adapters\n\
     \x20 spec-import <openapi|graphql>   read a spec from stdin -> inventory\n\
     \x20 ad-parse                   read an AD dump from stdin -> artifacts\n\
     \x20 import <adapter_id>        read tool output from stdin -> findings\n\
     \x20 modules                    list FableScope modules\n\
     \x20 version                    print version\n"
}

fn read_stdin() -> String {
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    s
}

fn print_json(v: &serde_json::Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into()));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");
    let rest = &args[1.min(args.len())..];

    let result: Result<serde_json::Value, String> = match cmd {
        "hash-id" => rest
            .first()
            .ok_or_else(|| "hash-id requires <hash>".to_string())
            .and_then(|h| serde_json::to_value(fs_tools::identify_hashes(h)).map_err(|e| e.to_string())),
        "cvss" => rest
            .first()
            .ok_or_else(|| "cvss requires <vector>".to_string())
            .and_then(|v| fs_reporting::calculate_cvss_v31(v).map_err(|e| e.to_string()))
            .and_then(|s| serde_json::to_value(s).map_err(|e| e.to_string())),
        "passwords" => {
            let len: usize = rest.first().and_then(|s| s.parse().ok()).unwrap_or(16);
            let count: usize = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
            let policy = fs_tools::PasswordPolicy { length: len, ..Default::default() };
            serde_json::to_value(fs_tools::generate_passwords(&policy, count, None)).map_err(|e| e.to_string())
        }
        "passphrase" => {
            let n: usize = rest.first().and_then(|s| s.parse().ok()).unwrap_or(5);
            let words = fs_tools::password::default_passphrase_words();
            serde_json::to_value(fs_tools::generate_passphrase(&words, n, "-", None)).map_err(|e| e.to_string())
        }
        "mutate" => rest
            .first()
            .ok_or_else(|| "mutate requires <word>".to_string())
            .map(|w| fs_recon::generate_payloads(w, &fs_recon::default_strategies()))
            .and_then(|p| serde_json::to_value(p).map_err(|e| e.to_string())),
        "subdomains" => rest
            .first()
            .ok_or_else(|| "subdomains requires <root>".to_string())
            .map(|root| {
                let scope = fs_core::ScopePolicy { allow: vec![root.clone()], deny: vec![] };
                fs_recon::subdomain_candidates(root, &[], &[], &scope, 500)
            })
            .and_then(|c| serde_json::to_value(c).map_err(|e| e.to_string())),
        "wordlist-sources" => serde_json::to_value(fs_wordlists::builtin_sources()).map_err(|e| e.to_string()),
        "import-adapters" => serde_json::to_value(fs_adapters::builtin_adapters()).map_err(|e| e.to_string()),
        "modules" => serde_json::to_value(fs_core::builtin_modules()).map_err(|e| e.to_string()),
        "spec-import" => {
            let kind = rest.first().map(|s| s.as_str()).unwrap_or("openapi");
            let body = read_stdin();
            match kind {
                "graphql" => serde_json::to_value(fs_recon::parse_graphql_sdl(&body)).map_err(|e| e.to_string()),
                _ => match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(doc) => serde_json::to_value(fs_recon::parse_openapi(&doc)).map_err(|e| e.to_string()),
                    Err(e) => Err(format!("invalid JSON: {e}")),
                },
            }
        }
        "ad-parse" => {
            let body = read_stdin();
            let arts = fs_ad::parse_dump(&body);
            let summary = fs_ad::summarize(&arts);
            Ok(serde_json::json!({"summary": summary, "artifacts": arts}))
        }
        "import" => match rest.first() {
            None => Err("import requires <adapter_id>".to_string()),
            Some(id) => {
                let reg = fs_adapters::AdapterRegistry::with_builtins();
                match reg.get(id) {
                    None => Err(format!("unknown adapter: {id}")),
                    Some(m) => {
                        let m = m.clone();
                        let body = read_stdin();
                        serde_json::to_value(fs_adapters::parse_with(&m, &body)).map_err(|e| e.to_string())
                    }
                }
            }
        },
        "version" => Ok(serde_json::json!({"name": "fablescope", "version": env!("CARGO_PKG_VERSION")})),
        "help" | "-h" | "--help" => {
            print!("{}", usage());
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command: {other}\n\n{}", usage())),
    };

    match result {
        Ok(v) => {
            print_json(&v);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
