// src/lib.rs - multi-concept Rust fixture for parser validation
// Exercises: lifetimes, borrows, unsafe blocks, control flow (if/match/loop/while/for),
// closures, trait impls, macros, and taint-source → taint-sink paths.

use std::collections::HashMap;
use std::env;
use std::io::{self, Read};
use std::process::Command;

// ── Constants & type aliases ──────────────────────────────────────────────────
pub type ByteSlice<'a> = &'a [u8];
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// ── Derive + repr macro exercises ────────────────────────────────────────────
#[derive(Debug, Clone)]
#[repr(C)]
pub struct Config<'a> {
    pub host: &'a str,
    pub port: u16,
    pub secret_key: &'a str,   // PII-sensitive field
}

#[derive(Debug)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub token: String,         // PII-sensitive field
}

// ── Trait declaration ─────────────────────────────────────────────────────────
pub trait Processor {
    fn process(&self, input: &str) -> Result<String>;
    fn validate(&self, data: &[u8]) -> bool;
}

pub unsafe trait RawAccess {
    unsafe fn read_raw(&self, ptr: *const u8, len: usize) -> Vec<u8>;
}

// ── Trait impl with lifetimes ─────────────────────────────────────────────────
pub struct CommandRunner<'a> {
    pub config: &'a Config<'a>,
    cache: HashMap<String, CacheEntry>,
}

impl<'a> CommandRunner<'a> {
    pub fn new(config: &'a Config<'a>) -> Self {
        CommandRunner {
            config,
            cache: HashMap::new(),
        }
    }

    // Taint path: env::var → Command::new → sink
    pub fn run_from_env(&self) -> Result<String> {
        let cmd_name = env::var("CMD").unwrap_or_default();        // taint SOURCE
        let output = Command::new(&cmd_name).output()?;           // taint SINK
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    // Control flow: if / else
    pub fn check_permission(&self, user: &str) -> bool {
        let token = env::var("AUTH_TOKEN").unwrap_or_default();    // taint SOURCE
        if token.is_empty() {
            return false;
        } else if user == "admin" {
            return true;
        } else {
            self.validate_token(&token)
        }
    }

    // Control flow: match
    pub fn dispatch(&self, cmd: &str) -> Result<String> {
        let arg = env::var("ARG").unwrap_or_default();             // taint SOURCE
        match cmd {
            "run"  => self.execute_cmd(&arg),
            "echo" => Ok(arg.clone()),
            "nop"  => Ok(String::new()),
            _      => Err("unknown command".into()),
        }
    }

    // Control flow: loop + break
    pub fn retry_until_success(&self, input: &str) -> Result<String> {
        let mut attempts = 0usize;
        loop {
            if attempts >= 3 {
                break;
            }
            match self.process(input) {
                Ok(v)  => return Ok(v),
                Err(_) => attempts += 1,
            }
        }
        Err("max retries exceeded".into())
    }

    // Control flow: while
    pub fn drain_stream(&self, reader: &mut dyn Read) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 512];
        while let Ok(n) = reader.read(&mut chunk) {
            if n == 0 { break; }
            buf.extend_from_slice(&chunk[..n]);
        }
        buf
    }

    // Control flow: for iterator
    pub fn batch_execute(&self, commands: &[&str]) -> Vec<Result<String>> {
        commands.iter().map(|c| self.execute_cmd(c)).collect()
    }

    // Closure exercise
    pub fn filter_results(&self, results: Vec<String>) -> Vec<String> {
        results.into_iter().filter(|r| !r.is_empty()).collect()
    }

    fn validate_token(&self, token: &str) -> bool {
        !token.is_empty() && token.len() > 8
    }

    fn execute_cmd(&self, cmd: &str) -> Result<String> {
        let output = Command::new(cmd).output()?;                  // taint SINK
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

impl<'a> Processor for CommandRunner<'a> {
    fn process(&self, input: &str) -> Result<String> {
        if input.is_empty() {
            return Err("empty input".into());
        }
        self.execute_cmd(input)
    }

    fn validate(&self, data: &[u8]) -> bool {
        !data.is_empty()
    }
}

// ── Unsafe impl ───────────────────────────────────────────────────────────────
unsafe impl<'a> RawAccess for CommandRunner<'a> {
    unsafe fn read_raw(&self, ptr: *const u8, len: usize) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(ptr, len);          // unsafe deref
        slice.to_vec()
    }
}

// ── Standalone unsafe function ────────────────────────────────────────────────
pub unsafe fn transmute_buffer(buf: *mut u8, len: usize) -> &'static mut [u8] {
    std::mem::transmute(std::slice::from_raw_parts_mut(buf, len)) // unsafe transmute
}

// ── Macro definitions ─────────────────────────────────────────────────────────
macro_rules! log_and_run {
    ($cmd:expr) => {
        println!("running: {}", $cmd);
        Command::new($cmd).output()
    };
}

macro_rules! taint_exec {
    ($src:expr) => {{
        let val = std::env::var($src).unwrap_or_default();
        Command::new(&val).output()
    }};
}

// ── Free function using macros ────────────────────────────────────────────────
pub fn run_macro_path() {
    let _ = taint_exec!("USER_CMD");                               // macro taint path
    let _ = log_and_run!("ls");
}

// ── Generic function with where clause ───────────────────────────────────────
pub fn process_all<'a, T>(items: &'a [T], f: impl Fn(&'a T) -> String) -> Vec<String>
where
    T: std::fmt::Debug + 'a,
{
    items.iter().map(f).collect()
}
