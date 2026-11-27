//! Serial ports as a terminal byte backend (B7, `docs/plans/B7-TELNET-SERIAL.md`): settings,
//! port listing and validation of typed port names. The terminal side (reader thread, reopen)
//! is in `terminal.rs`.
use std::time::Duration;

use serde::Serialize;

use crate::error::{CoreError, Result};
use crate::model::Settings;

/// How often the apps refresh the port list while a picker is open.
pub const SERIAL_PORT_POLL: Duration = Duration::from_secs(2);
/// Read timeout of the reader thread, so closing a tab joins it promptly.
pub const SERIAL_READ_TIMEOUT: Duration = Duration::from_secs(1);
pub const DEFAULT_BAUD: u32 = 9600;
pub const MIN_BAUD: u32 = 50;
pub const MAX_BAUD: u32 = 4_000_000;
/// Offered in the baud list; any value in `MIN_BAUD..=MAX_BAUD` may be typed.
pub const COMMON_BAUDS: &[u32] = &[300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Parity {
    None,
    Odd,
    Even,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Flow {
    None,
    Software,
    Hardware,
}

/// What the Enter key sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LineEnding {
    Cr,
    Lf,
    CrLf,
}

impl LineEnding {
    pub fn bytes(self) -> &'static [u8] {
        match self {
            LineEnding::Cr => b"\r",
            LineEnding::Lf => b"\n",
            LineEnding::CrLf => b"\r\n",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialSettings {
    pub port: String,
    pub baud: u32,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    pub flow: Flow,
    pub local_echo: bool,
    pub enter: LineEnding,
}

impl SerialSettings {
    /// Resolve a serial connection's (inherited) settings, validating every value.
    pub fn from_settings(s: &Settings) -> Result<Self> {
        let port = s.serial_port.clone().filter(|p| !p.trim().is_empty()).ok_or_else(|| CoreError::Invalid("Choose a serial port.".into()))?;
        let baud = s.serial_baud.unwrap_or(DEFAULT_BAUD);
        if !(MIN_BAUD..=MAX_BAUD).contains(&baud) {
            return Err(CoreError::Invalid(format!("Baud rate {baud} is out of range ({MIN_BAUD}–{MAX_BAUD}).")));
        }
        let data_bits = s.serial_data_bits.unwrap_or(8);
        if !(5..=8).contains(&data_bits) {
            return Err(CoreError::Invalid(format!("Data bits must be 5 to 8, not {data_bits}.")));
        }
        let stop_bits = s.serial_stop_bits.unwrap_or(1);
        if !(1..=2).contains(&stop_bits) {
            return Err(CoreError::Invalid(format!("Stop bits must be 1 or 2, not {stop_bits}.")));
        }
        Ok(SerialSettings {
            port: port.trim().to_string(),
            baud,
            data_bits,
            parity: parse_parity(s.serial_parity.as_deref())?,
            stop_bits,
            flow: parse_flow(s.serial_flow.as_deref())?,
            local_echo: s.serial_local_echo.unwrap_or(false),
            enter: parse_enter(s.serial_enter.as_deref())?,
        })
    }

    /// Short status for the tab, e.g. `COM3 · 115200 8N1`.
    pub fn status_line(&self) -> String {
        let p = match self.parity {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
        };
        let name = self.port.rsplit('/').next().unwrap_or(&self.port);
        format!("{name} · {} {}{p}{}", self.baud, self.data_bits, self.stop_bits)
    }
}

pub fn parse_parity(v: Option<&str>) -> Result<Parity> {
    match v.unwrap_or("none") {
        "none" => Ok(Parity::None),
        "odd" => Ok(Parity::Odd),
        "even" => Ok(Parity::Even),
        o => Err(CoreError::Invalid(format!("Parity `{o}` is not one of none, odd, even."))),
    }
}

pub fn parse_flow(v: Option<&str>) -> Result<Flow> {
    match v.unwrap_or("none") {
        "none" => Ok(Flow::None),
        "software" => Ok(Flow::Software),
        "hardware" => Ok(Flow::Hardware),
        o => Err(CoreError::Invalid(format!("Flow control `{o}` is not one of none, software, hardware."))),
    }
}

pub fn parse_enter(v: Option<&str>) -> Result<LineEnding> {
    match v.unwrap_or("cr") {
        "cr" => Ok(LineEnding::Cr),
        "lf" => Ok(LineEnding::Lf),
        "crlf" => Ok(LineEnding::CrLf),
        o => Err(CoreError::Invalid(format!("Enter sends `{o}`: use cr, lf or crlf."))),
    }
}

/// Check a typed Windows port name: `COM1`–`COM256` only. Returns the name to open
/// (`\\.\COMn`, which also works above COM9).
pub fn validate_windows_port(name: &str) -> Result<String> {
    let upper = name.trim().to_ascii_uppercase();
    let n = upper.strip_prefix(r"\\.\").unwrap_or(&upper).strip_prefix("COM").and_then(|d| (!d.starts_with('0')).then_some(d)).and_then(|d| d.parse::<u16>().ok());
    match n {
        Some(n @ 1..=256) => Ok(format!(r"\\.\COM{n}")),
        _ => Err(CoreError::Invalid(format!("`{name}` is not a serial port name (COM1 to COM256)."))),
    }
}

/// Check a typed Unix port name: after resolving links, only `/dev/cu.*` and `/dev/tty.*`
/// (macOS), plus `/dev/ttyS*`, `/dev/ttyUSB*`, `/dev/ttyACM*` on Linux, are accepted. Disks,
/// `/dev/null`, random devices and any path outside `/dev` are refused.
pub fn validate_unix_port(name: &str) -> Result<String> {
    let refuse = || CoreError::Invalid(format!("`{name}` is not a serial port (expected /dev/cu.* or /dev/tty.*)."));
    let path = std::path::Path::new(name.trim());
    if !path.is_absolute() {
        return Err(refuse());
    }
    let real = std::fs::canonicalize(path).map_err(|_| CoreError::NotFound(format!("Port not found: {name}")))?;
    let real_str = real.to_str().ok_or_else(refuse)?;
    if is_serial_device_path(real_str) || is_test_pty_path(real_str) {
        Ok(real_str.to_string())
    } else {
        Err(refuse())
    }
}

/// The name rule alone, without touching the file system.
pub fn is_serial_device_path(p: &str) -> bool {
    let Some(file) = p.strip_prefix("/dev/") else { return false };
    if file.contains('/') {
        return false;
    }
    const PREFIXES: &[&str] = &["cu.", "tty.", "ttyS", "ttyUSB", "ttyACM"];
    PREFIXES.iter().any(|pre| file.strip_prefix(pre).is_some_and(|rest| !rest.is_empty()))
}

/// Driver suites only (B7-LIVE): a pseudo-terminal pair stands in for a serial cable, so a
/// test-hooks core also opens `/dev/ttys<n>` (macOS) and `/dev/pts/<n>` (Linux). Release cores are
/// never built with `test-hooks` (bundle.sh refuses them), so there this is always false.
fn is_test_pty_path(p: &str) -> bool {
    if !cfg!(feature = "test-hooks") {
        return false;
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    p.strip_prefix("/dev/ttys").is_some_and(digits) || p.strip_prefix("/dev/pts/").is_some_and(digits)
}

/// Validate a typed port name for this operating system.
pub fn validate_port(name: &str) -> Result<String> {
    if cfg!(windows) {
        validate_windows_port(name)
    } else {
        validate_unix_port(name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SerialPortInfo {
    /// What to store and open: `/dev/cu.usbserial-A1`, `COM3`.
    pub name: String,
    /// Human description, e.g. "USB-Serial (FTDI)"; may be empty.
    pub description: String,
    /// `usb`, `pci`, `bluetooth` or `unknown`.
    pub kind: String,
}

/// Ports on this machine. On macOS only `/dev/cu.*` (the `tty.*` twins wait for carrier detect).
pub fn list_serial_ports() -> Result<Vec<SerialPortInfo>> {
    let ports = serialport::available_ports().map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;
    let mut out: Vec<SerialPortInfo> = ports
        .into_iter()
        .filter(|p| !cfg!(target_os = "macos") || p.port_name.starts_with("/dev/cu."))
        .map(|p| {
            let (kind, description) = match p.port_type {
                serialport::SerialPortType::UsbPort(u) => {
                    let d = [u.product, u.manufacturer.map(|m| format!("({m})"))].into_iter().flatten().collect::<Vec<_>>().join(" ");
                    ("usb", d)
                }
                serialport::SerialPortType::PciPort => ("pci", String::new()),
                serialport::SerialPortType::BluetoothPort => ("bluetooth", String::new()),
                serialport::SerialPortType::Unknown => ("unknown", String::new()),
            };
            SerialPortInfo { name: p.port_name, description, kind: kind.into() }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// Open a port with these settings (validated name, read timeout set).
pub(crate) fn open_port(s: &SerialSettings) -> Result<Box<dyn serialport::SerialPort>> {
    let path = validate_port(&s.port)?;
    let data_bits = match s.data_bits {
        5 => serialport::DataBits::Five,
        6 => serialport::DataBits::Six,
        7 => serialport::DataBits::Seven,
        _ => serialport::DataBits::Eight,
    };
    let parity = match s.parity {
        Parity::None => serialport::Parity::None,
        Parity::Odd => serialport::Parity::Odd,
        Parity::Even => serialport::Parity::Even,
    };
    let stop = if s.stop_bits == 2 { serialport::StopBits::Two } else { serialport::StopBits::One };
    let flow = match s.flow {
        Flow::None => serialport::FlowControl::None,
        Flow::Software => serialport::FlowControl::Software,
        Flow::Hardware => serialport::FlowControl::Hardware,
    };
    serialport::new(&path, s.baud)
        .data_bits(data_bits)
        .parity(parity)
        .stop_bits(stop)
        .flow_control(flow)
        .timeout(SERIAL_READ_TIMEOUT)
        .open()
        .map_err(|e| open_error(&s.port, e))
}

fn open_error(port: &str, e: serialport::Error) -> CoreError {
    use serialport::ErrorKind;
    match e.kind() {
        ErrorKind::NoDevice => CoreError::NotFound(format!("Port not found: {port}")),
        ErrorKind::Io(std::io::ErrorKind::NotFound) => CoreError::NotFound(format!("Port not found: {port}")),
        ErrorKind::Io(std::io::ErrorKind::PermissionDenied) => {
            if cfg!(windows) {
                CoreError::Invalid(format!("{port} is in use by another program."))
            } else {
                CoreError::Invalid(format!("Access to {port} was refused."))
            }
        }
        _ if e.description.to_ascii_lowercase().contains("busy") => CoreError::Invalid(format!("{port} is in use by another program.")),
        _ => CoreError::Io(std::io::Error::other(format!("{port}: {}", e.description))),
    }
}

/// Whether a read error means "nothing arrived yet" (keep reading) rather than "device gone".
pub(crate) fn is_idle_read(e: &std::io::Error) -> bool {
    matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted)
}

#[cfg(test)]
#[path = "serial_tests.rs"]
mod tests;
