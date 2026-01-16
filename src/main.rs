use std::fs;
use std::process;

#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use doas::{authenticate, check_permission, find_rule, get_current_user, parse_config, run_command};

#[cfg(unix)]
#[derive(Parser)]
#[command(name = "doas")]
#[command(about = "Run commands as another user")]
struct Args {
    /// User to run as
    #[arg(short = 'u', long)]
    user: Option<String>,

    /// Config file
    #[arg(short = 'C', long)]
    config: Option<String>,

    /// Command to run
    #[arg(required = true)]
    command: Vec<String>,
}

#[cfg(not(unix))]
fn main() {
    eprintln!("doas is only supported on Unix-like systems");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    let args = Args::parse();

    let config_path = args.config.unwrap_or_else(|| {
        if fs::metadata("/etc/doas.conf").is_ok() {
            "/etc/doas.conf".to_string()
        } else {
            "/usr/local/etc/doas.conf".to_string()
        }
    });

    let rules = parse_config(&config_path).unwrap_or_else(|e| {
        eprintln!("Error reading config: {}", e);
        process::exit(1);
    });

    let current_user = get_current_user();
    let target_user = args.user.unwrap_or_else(|| "root".to_string());

    if !check_permission(&rules, &current_user, &target_user) {
        eprintln!("doas: permission denied");
        process::exit(1);
    }

    let rule = find_rule(&rules, &current_user, &target_user).unwrap();

    if !rule.nopass {
        if !authenticate(&current_user) {
            eprintln!("doas: authentication failed");
            process::exit(1);
        }
    }

    run_command(&args.command, &target_user, rule.keepenv);
}
