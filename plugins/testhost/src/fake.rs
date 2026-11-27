//! Fakes for what the core would reach: a server and a login.

/// A server the plugin's streams reach. One `connect` per stream.
/// One `http.send` as the fake server sees it: what the core would write, with the login header
/// already added when `with_login` was set and the test configured a login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeHttpRequest {
    pub method: String,
    pub port: u16,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The value of the login header, when one was added (the plugin never sees it).
    pub login: Option<String>,
}

/// A fake server's answer to `exec.run`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeExecOutput {
    pub exit: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A fake server's answer to `http.send`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub trait FakeServer: Send {
    /// Answers one `http.send` (API 1.1). By default the server speaks no HTTP.
    fn http(&mut self, _req: &FakeHttpRequest) -> Result<FakeHttpResponse, String> {
        Err("this fake server speaks no HTTP".into())
    }
    /// Runs one declared command (API 1.5): the template id and its arguments as the plugin gave
    /// them. By default the server has no SSH.
    fn exec(&mut self, _template: &str, _args: &[(String, String)]) -> Result<FakeExecOutput, String> {
        Err("this fake server runs no commands".into())
    }
    /// Opens a connection on `port`, or refuses it with a reason.
    fn connect(&mut self, port: u16) -> Result<Box<dyn FakeConnection>, String>;
}

/// One connection to a [`FakeServer`].
pub trait FakeConnection: Send {
    /// Takes bytes from the plugin.
    fn write(&mut self, data: &[u8]) -> Result<(), String>;
    /// Bytes for the plugin: `None` while there is nothing yet, an empty vector when the
    /// server closed the connection.
    fn read(&mut self, max: usize) -> Option<Vec<u8>>;
    /// The plugin asked for TLS. A fake accepts by default.
    fn start_tls(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// Refuses every connection.
pub struct NoServer;

impl FakeServer for NoServer {
    fn connect(&mut self, port: u16) -> Result<Box<dyn FakeConnection>, String> {
        Err(format!("no server listens on port {port}"))
    }
}

/// Answers each line with the same line in upper case.
pub struct LineEcho;

impl FakeServer for LineEcho {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn FakeConnection>, String> {
        Ok(Box::new(LineEchoConnection { line: Vec::new(), out: Vec::new() }))
    }
}

struct LineEchoConnection {
    line: Vec<u8>,
    out: Vec<u8>,
}

impl FakeConnection for LineEchoConnection {
    fn write(&mut self, data: &[u8]) -> Result<(), String> {
        for &b in data {
            self.line.push(b);
            if b == b'\n' {
                self.out.extend(self.line.drain(..).map(|c| c.to_ascii_uppercase()));
            }
        }
        Ok(())
    }

    fn read(&mut self, max: usize) -> Option<Vec<u8>> {
        if self.out.is_empty() {
            return None;
        }
        let n = max.min(self.out.len());
        Some(self.out.drain(..n).collect())
    }
}
