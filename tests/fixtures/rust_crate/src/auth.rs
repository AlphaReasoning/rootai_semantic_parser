// src/auth.rs - second file to test cross-file symbol resolution
use crate::Result;
use std::env;
use std::io::stdin;

pub struct AuthService {
    pub secret: String,        // PII-sensitive
    pub password: String,      // PII-sensitive
}

impl AuthService {
    pub fn new() -> Self {
        let secret = env::var("APP_SECRET").unwrap_or_default(); // taint SOURCE
        AuthService {
            secret,
            password: String::new(),
        }
    }

    // if / match control flow with taint
    pub fn authenticate(&self, user_input: &str) -> bool {
        if user_input.is_empty() {
            return false;
        }
        match user_input {
            "admin" => true,
            s if s == self.secret => true,
            _ => false,
        }
    }

    // for loop + taint
    pub fn check_all_tokens(&self, tokens: &[&str]) -> bool {
        for token in tokens.iter() {
            if *token == self.secret {
                return true;
            }
        }
        false
    }

    // stdin taint source
    pub fn read_credential(&self) -> String {
        let mut buf = String::new();
        stdin().read_line(&mut buf).unwrap_or(0);  // taint SOURCE
        buf.trim().to_string()
    }
}

pub fn validate_and_run(cmd: &str, token: &str) -> Result<()> {
    if token.len() < 8 {
        return Err("token too short".into());
    }
    // taint sink: Command used with externally-supplied cmd
    let _ = std::process::Command::new(cmd).output()?;
    Ok(())
}
