//! Telnet (RFC 854) as a terminal byte backend: option negotiation, IAC escaping, window size
//! (NAWS, RFC 1073), terminal type (RFC 1091) and the opt-in auto-login (B7,
//! `docs/plans/B7-TELNET-SERIAL.md`). Telnet is cleartext: it is off unless policy allows it
//! (`policy::telnet_allowed`), and a saved password is typed only after an explicit
//! per-connection opt-in, in the order `login:` then `password:`, once per connect.
use std::fmt;
use std::time::{Duration, Instant};

use crate::error::{CoreError, Result};
use crate::vault::Secret;

/// Longest wait for the TCP connection.
pub const TELNET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest wait for each login prompt when auto-login is on.
pub const TELNET_LOGIN_PROMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Default Telnet port.
pub const TELNET_PORT: u16 = 23;
/// Largest sub-negotiation we accept; a longer one ends the connection.
pub const MAX_SUBNEGOTIATION: usize = 1024;
/// Option commands in a row without any data byte before we treat it as a negotiation loop.
pub const MAX_NEGOTIATIONS_WITHOUT_DATA: u32 = 50;

const IAC: u8 = 255;
const DONT: u8 = 254;
const DO: u8 = 253;
const WONT: u8 = 252;
const WILL: u8 = 251;
const SB: u8 = 250;
const SE: u8 = 240;

const OPT_ECHO: u8 = 1;
const OPT_SGA: u8 = 3;
const OPT_TTYPE: u8 = 24;
const OPT_NAWS: u8 = 31;
const TTYPE_IS: u8 = 0;
const TTYPE_SEND: u8 = 1;

/// Saved login for the opt-in auto-login. The password is zeroised on drop and never printed.
#[derive(Clone)]
pub struct AutoLogin {
    pub username: String,
    pub password: Secret,
}

impl fmt::Debug for AutoLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AutoLogin").field("username", &self.username).field("password", &"***").finish()
    }
}

/// What a Telnet terminal connects to.
#[derive(Clone, Debug)]
pub struct TelnetOptions {
    pub host: String,
    pub port: u16,
    /// Sent for TTYPE, upper-case as RFC 1091 asks.
    pub term_type: String,
    pub connect_timeout: Duration,
    /// `Some` only when the connection itself has `telnet_send_password` on.
    pub auto_login: Option<AutoLogin>,
}

impl TelnetOptions {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        TelnetOptions { host: host.into(), port, term_type: "XTERM-256COLOR".into(), connect_timeout: TELNET_CONNECT_TIMEOUT, auto_login: None }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Data,
    Iac,
    /// After IAC WILL/WONT/DO/DONT: waiting for the option byte.
    Opt(u8),
    Sub,
    SubIac,
}

/// The protocol state of one Telnet connection. Pure: bytes in, bytes out, so it is unit-tested
/// without a socket.
#[derive(Debug)]
pub struct TelnetCodec {
    state: State,
    sub: Vec<u8>,
    /// Options we perform (WILL accepted by the server's DO).
    ours: [bool; 256],
    /// Options the server performs (its WILL we answered with DO).
    theirs: [bool; 256],
    negotiations: u32,
    size: (u16, u16),
    term_type: String,
}

/// Result of decoding a chunk from the server.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Decoded {
    /// Terminal data with Telnet commands removed.
    pub data: Vec<u8>,
    /// Bytes to send back to the server (negotiation answers).
    pub reply: Vec<u8>,
}

impl TelnetCodec {
    pub fn new(cols: u16, rows: u16, term_type: &str) -> Self {
        TelnetCodec { state: State::Data, sub: Vec::new(), ours: [false; 256], theirs: [false; 256], negotiations: 0, size: (cols, rows), term_type: term_type.to_string() }
    }

    /// Whether the server echoes (it said WILL ECHO and we agreed).
    pub fn server_echoes(&self) -> bool {
        self.theirs[OPT_ECHO as usize]
    }

    /// Decode bytes from the server. Fails on a negotiation loop or an oversized sub-negotiation;
    /// the caller then closes the connection.
    pub fn decode(&mut self, input: &[u8]) -> Result<Decoded> {
        let mut out = Decoded::default();
        for &b in input {
            match self.state {
                State::Data => {
                    if b == IAC {
                        self.state = State::Iac;
                    } else {
                        self.negotiations = 0;
                        out.data.push(b);
                    }
                }
                State::Iac => {
                    self.state = match b {
                        IAC => {
                            self.negotiations = 0;
                            out.data.push(IAC);
                            State::Data
                        }
                        WILL | WONT | DO | DONT => State::Opt(b),
                        SB => {
                            self.sub.clear();
                            State::Sub
                        }
                        // NOP, GA, AYT and the other one-byte commands carry nothing for us.
                        _ => State::Data,
                    };
                }
                State::Opt(cmd) => {
                    self.state = State::Data;
                    self.negotiations += 1;
                    if self.negotiations > MAX_NEGOTIATIONS_WITHOUT_DATA {
                        return Err(CoreError::Invalid("the Telnet server kept renegotiating options; the connection was closed".into()));
                    }
                    self.negotiate(cmd, b, &mut out.reply);
                }
                State::Sub => {
                    if b == IAC {
                        self.state = State::SubIac;
                    } else {
                        self.push_sub(b)?;
                    }
                }
                State::SubIac => match b {
                    SE => {
                        self.state = State::Data;
                        self.subnegotiation(&mut out.reply);
                    }
                    IAC => {
                        self.state = State::Sub;
                        self.push_sub(IAC)?;
                    }
                    // A malformed IAC inside SB: drop it and keep collecting.
                    _ => self.state = State::Sub,
                },
            }
        }
        Ok(out)
    }

    fn push_sub(&mut self, b: u8) -> Result<()> {
        if self.sub.len() >= MAX_SUBNEGOTIATION {
            return Err(CoreError::Invalid("the Telnet server sent an oversized option block; the connection was closed".into()));
        }
        self.sub.push(b);
        Ok(())
    }

    fn negotiate(&mut self, cmd: u8, opt: u8, reply: &mut Vec<u8>) {
        let i = opt as usize;
        match cmd {
            DO => {
                let supported = matches!(opt, OPT_TTYPE | OPT_NAWS | OPT_SGA);
                if supported {
                    if !self.ours[i] {
                        self.ours[i] = true;
                        reply.extend_from_slice(&[IAC, WILL, opt]);
                    }
                    if opt == OPT_NAWS {
                        reply.extend(self.naws_bytes());
                    }
                } else {
                    // Refuse; answer once per request is safe since we never agreed.
                    reply.extend_from_slice(&[IAC, WONT, opt]);
                }
            }
            DONT => {
                if self.ours[i] {
                    self.ours[i] = false;
                    reply.extend_from_slice(&[IAC, WONT, opt]);
                }
            }
            WILL => {
                if matches!(opt, OPT_ECHO | OPT_SGA) {
                    if !self.theirs[i] {
                        self.theirs[i] = true;
                        reply.extend_from_slice(&[IAC, DO, opt]);
                    }
                } else {
                    reply.extend_from_slice(&[IAC, DONT, opt]);
                }
            }
            WONT => {
                if self.theirs[i] {
                    self.theirs[i] = false;
                    reply.extend_from_slice(&[IAC, DONT, opt]);
                }
            }
            _ => {}
        }
    }

    fn subnegotiation(&mut self, reply: &mut Vec<u8>) {
        if self.sub.as_slice() == [OPT_TTYPE, TTYPE_SEND] && self.ours[OPT_TTYPE as usize] {
            reply.extend_from_slice(&[IAC, SB, OPT_TTYPE, TTYPE_IS]);
            reply.extend(self.term_type.bytes().filter(|b| b.is_ascii_graphic()));
            reply.extend_from_slice(&[IAC, SE]);
        }
        self.sub.clear();
    }

    fn naws_bytes(&self) -> Vec<u8> {
        let mut v = vec![IAC, SB, OPT_NAWS];
        for n in [self.size.0, self.size.1] {
            for b in n.to_be_bytes() {
                v.push(b);
                if b == IAC {
                    v.push(IAC);
                }
            }
        }
        v.extend_from_slice(&[IAC, SE]);
        v
    }

    /// The terminal was resized: the NAWS message to send, if the server asked for sizes.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Option<Vec<u8>> {
        self.size = (cols, rows);
        self.ours[OPT_NAWS as usize].then(|| self.naws_bytes())
    }

    /// Escape keyboard input for the wire: IAC doubled; a lone CR becomes CR NUL (RFC 854).
    pub fn encode_input(input: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(input.len() + 4);
        for (i, &b) in input.iter().enumerate() {
            match b {
                IAC => v.extend_from_slice(&[IAC, IAC]),
                b'\r' if input.get(i + 1) != Some(&b'\n') => v.extend_from_slice(b"\r\0"),
                _ => v.push(b),
            }
        }
        v
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LoginStage {
    WaitLogin,
    WaitPassword,
    Done,
}

/// Watches decoded server output for the login prompts and says what to type, strictly in the
/// order `login:` → username, then `password:` → password, each once per connect. A
/// `password:` prompt before the username was sent is ignored; each wait gives up after
/// `TELNET_LOGIN_PROMPT_TIMEOUT`.
pub struct LoginWatcher {
    login: AutoLogin,
    stage: LoginStage,
    since: Instant,
    timeout: Duration,
    line: String,
    in_escape: bool,
}

impl fmt::Debug for LoginWatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginWatcher").field("login", &self.login).field("stage", &self.stage).finish()
    }
}

const MAX_PROMPT_LINE: usize = 256;

impl LoginWatcher {
    pub fn new(login: AutoLogin) -> Self {
        Self::with_timeout(login, TELNET_LOGIN_PROMPT_TIMEOUT, Instant::now())
    }

    pub fn with_timeout(login: AutoLogin, timeout: Duration, now: Instant) -> Self {
        LoginWatcher { login, stage: LoginStage::WaitLogin, since: now, timeout, line: String::new(), in_escape: false }
    }

    pub fn done(&self) -> bool {
        self.stage == LoginStage::Done
    }

    /// Feed decoded output; returns the bytes to type now (username or password plus CR), if any.
    pub fn feed(&mut self, data: &[u8], now: Instant) -> Option<Vec<u8>> {
        if self.stage == LoginStage::Done {
            return None;
        }
        if now.duration_since(self.since) > self.timeout {
            self.stage = LoginStage::Done;
            return None;
        }
        for &b in data {
            if self.in_escape {
                // CSI and similar end with a letter; good enough to keep prompt text clean.
                if b.is_ascii_alphabetic() || b == b'~' {
                    self.in_escape = false;
                }
                continue;
            }
            match b {
                0x1b => self.in_escape = true,
                b'\r' | b'\n' => self.line.clear(),
                b if b.is_ascii_graphic() || b == b' ' => {
                    if self.line.len() >= MAX_PROMPT_LINE {
                        self.line.drain(..MAX_PROMPT_LINE / 2);
                    }
                    self.line.push(b as char);
                }
                _ => {}
            }
        }
        let tail = self.line.trim_end().to_ascii_lowercase();
        match self.stage {
            LoginStage::WaitLogin if tail.ends_with("login:") => {
                self.stage = LoginStage::WaitPassword;
                self.since = now;
                self.line.clear();
                let mut v = self.login.username.as_bytes().to_vec();
                v.push(b'\r');
                Some(v)
            }
            LoginStage::WaitPassword if tail.ends_with("password:") => {
                self.stage = LoginStage::Done;
                self.line.clear();
                let mut v = self.login.password.expose().as_bytes().to_vec();
                v.push(b'\r');
                Some(v)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "telnet_tests.rs"]
mod tests;
