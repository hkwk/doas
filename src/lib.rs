use std::collections::HashMap;
use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::process::{self, Command};

use libc::{getuid, setgid, setuid};
use pam::Authenticator;
use std::os::unix::process::CommandExt;

#[derive(Debug)]
pub struct Rule {
    pub permit: bool,
    pub nopass: bool,
    pub keepenv: bool,
    #[allow(dead_code)]
    pub nolog: bool,
    pub identity: String,
    pub target: String,
}

pub fn get_current_user() -> String {
    unsafe {
        let uid = getuid();
        let passwd = libc::getpwuid(uid);
        if passwd.is_null() {
            panic!("Failed to get current user");
        }
        CStr::from_ptr((*passwd).pw_name).to_string_lossy().to_string()
    }
}

pub fn parse_config(path: &str) -> Result<Vec<Rule>, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let mut rules = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace().peekable();
        let Some(action) = parts.next() else { continue };
        let permit = match action {
            "permit" => true,
            "deny" => false,
            _ => continue,
        };

        let mut nopass = false;
        let mut keepenv = false;
        let mut nolog = false;
        let mut identity: Option<String> = None;

        while let Some(token) = parts.next() {
            match token {
                "nopass" => nopass = true,
                "keepenv" => keepenv = true,
                "nolog" => nolog = true,
                _ => {
                    identity = Some(token.to_string());
                    break;
                }
            }
        }

        let Some(identity) = identity else { continue };
        if parts.next() != Some("as") {
            continue;
        }
        let Some(target) = parts.next() else { continue };

        rules.push(Rule {
            permit,
            nopass,
            keepenv,
            nolog,
            identity,
            target: target.to_string(),
        });
    }
    Ok(rules)
}

pub fn check_permission(rules: &[Rule], identity: &str, target: &str) -> bool {
    for rule in rules {
        if rule.identity == identity && rule.target == target {
            return rule.permit;
        }
    }
    false
}

pub fn find_rule<'a>(rules: &'a [Rule], identity: &str, target: &str) -> Option<&'a Rule> {
    rules.iter().find(|r| r.identity == identity && r.target == target)
}

pub fn authenticate(_user: &str) -> bool {
    let mut auth = Authenticator::with_password("doas").unwrap();
    auth.authenticate().is_ok() && auth.open_session().is_ok()
}

pub fn run_command(command: &[String], target_user: &str, keepenv: bool) {
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
    env_vars.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env_vars.insert("USER".to_string(), target_user.to_string());
    env_vars.insert("HOME".to_string(), get_user_home(target_user));
    env_vars.insert("SHELL".to_string(), get_user_shell(target_user));

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]);
    cmd.env_clear();
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    let err = cmd.exec();
    eprintln!("doas: failed to exec {}: {}", command[0], err);
    process::exit(1);
}

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
