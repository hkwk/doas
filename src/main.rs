use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Write};
use std::process::{self, Command};

#[cfg(unix)]
use clap::Parser;
#[cfg(unix)]
use libc::{getuid, setuid, setgid, execvp, fork, waitpid, WIFEXITED, WEXITSTATUS};
#[cfg(unix)]
use pam::Authenticator;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

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

#[cfg(unix)]
#[derive(Debug)]
struct Rule {
    permit: bool,
    nopass: bool,
    keepenv: bool,
    nolog: bool,
    identity: String,
    target: String,
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

#[cfg(unix)]
fn get_current_user() -> String {
    unsafe {
        let uid = getuid();
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() {
            panic!("Failed to get current user");
        }
        CStr::from_ptr((*passwd).pw_name).to_string_lossy().to_string()
    }
}

#[cfg(unix)]
fn parse_config(path: &str) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut rules = Vec::new();
    let re = Regex::new(r"^(permit|deny)\s+(nopass\s+)?(?:keepenv\s+)?(?:nolog\s+)?(\w+)\s+as\s+(\w+)$")?;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(caps) = re.captures(line) {
            let permit = &caps[1] == "permit";
            let nopass = caps.get(2).is_some();
            let keepenv = caps.get(3).is_some();
            let nolog = caps.get(4).is_some();
            let identity = caps[5].to_string();
            let target = caps[6].to_string();
            rules.push(Rule {
                permit,
                nopass,
                keepenv,
                nolog,
                identity,
                target,
            });
        }
    }
    Ok(rules)
}

#[cfg(unix)]
fn check_permission(rules: &[Rule], identity: &str, target: &str) -> bool {
    for rule in rules {
        if rule.identity == identity && rule.target == target {
            return rule.permit;
        }
    }
    false
}

#[cfg(unix)]
fn find_rule<'a>(rules: &'a [Rule], identity: &str, target: &str) -> Option<&'a Rule> {
    rules.iter().find(|r| r.identity == identity && r.target == target)
}

#[cfg(unix)]
fn authenticate(_user: &str) -> bool {
    let mut auth = Authenticator::with_service("doas").unwrap();
    auth.authenticate().is_ok() && auth.open_session().is_ok()
}

#[cfg(unix)]
fn run_command(command: &[String], target_user: &str, keepenv: bool) {
    let uid = get_user_uid(target_user);
    let gid = get_user_gid(target_user);

    unsafe {
        if setgid(gid) != 0 {
            eprintln!("doas: failed to set gid");
            process::exit(1);
        }
        if setuid(uid) != 0 {
            eprintln!("doas: failed to set uid");
            process::exit(1);
        }
    }

    let mut env_vars = if keepenv {
        env::vars().collect::<HashMap<_, _>>()
    } else {
        HashMap::new()
    };
    // Add some basic env vars
    env_vars.insert("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    env_vars.insert("USER".to_string(), target_user.to_string());
    env_vars.insert("HOME".to_string(), get_user_home(target_user));
    env_vars.insert("SHELL".to_string(), get_user_shell(target_user));

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    cmd.exec();
}

#[cfg(unix)]
fn get_user_uid(user: &str) -> libc::uid_t {
    unsafe {
        let c_user = CString::new(user).unwrap();
        let passwd = libc::getpwnam(c_user.as_ptr());
        if passwd.is_null() {
            panic!("User {} not found", user);
        }
        (*passwd).pw_uid
    }
}

#[cfg(unix)]
fn get_user_gid(user: &str) -> libc::gid_t {
    unsafe {
        let c_user = CString::new(user).unwrap();
        let passwd = libc::getpwnam(c_user.as_ptr());
        if passwd.is_null() {
            panic!("User {} not found", user);
        }
        (*passwd).pw_gid
    }
}

#[cfg(unix)]
fn get_user_home(user: &str) -> String {
    unsafe {
        let c_user = CString::new(user).unwrap();
        let passwd = libc::getpwnam(c_user.as_ptr());
        if passwd.is_null() {
            "/".to_string()
        } else {
            CStr::from_ptr((*passwd).pw_dir).to_string_lossy().to_string()
        }
    }
}

#[cfg(unix)]
fn get_user_shell(user: &str) -> String {
    unsafe {
        let c_user = CString::new(user).unwrap();
        let passwd = libc::getpwnam(c_user.as_ptr());
        if passwd.is_null() {
            "/bin/sh".to_string()
        } else {
            CStr::from_ptr((*passwd).pw_shell).to_string_lossy().to_string()
        }
    }
}
