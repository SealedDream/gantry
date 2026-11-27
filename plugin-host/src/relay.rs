//! The two directions of the pipe inside the helper.
//!
//! - Writing: one `Link`, shared by the reader thread (pongs) and the plugin thread.
//! - Reading: one thread reads every frame. It answers `Ping` itself, so a plugin busy in a long
//!   call is never taken for a hung helper (PLUG-01 decision 5), and passes everything else on.
//!   When the pipe closes, the core says Shutdown, or a frame is bad, the helper leaves at once.

use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use bastion_plugin_host::proto::{read_frame, write_frame, ToCore, ToHelper, Value};

pub struct Link {
    out: Mutex<BufWriter<File>>,
}

impl Link {
    pub fn new(out: File) -> Link {
        Link { out: Mutex::new(BufWriter::new(out)) }
    }

    pub fn send(&self, message: &ToCore) -> std::io::Result<()> {
        let mut out = self.out.lock().unwrap_or_else(|e| e.into_inner());
        write_frame(&mut *out, &message.encode())
    }
}

/// What the reader thread passes on.
pub enum Work {
    Message(ToHelper),
    Reply { seq: u64, results: Vec<Value> },
}

/// The input pipe ended or the core said Shutdown: the plugin stops with the helper.
const EXIT_PIPE_CLOSED: i32 = 0;
const EXIT_BAD_FRAME: i32 = 2;

pub fn start_reader(input: File, link: Arc<Link>) -> mpsc::Receiver<Work> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut input = BufReader::new(input);
        loop {
            let frame = match read_frame(&mut input) {
                Ok(Some(frame)) => frame,
                Ok(None) => std::process::exit(EXIT_PIPE_CLOSED),
                Err(_) => std::process::exit(EXIT_BAD_FRAME),
            };
            let work = match ToHelper::decode(&frame) {
                Ok(ToHelper::Ping(n)) => {
                    if link.send(&ToCore::Pong(n)).is_err() {
                        std::process::exit(EXIT_PIPE_CLOSED);
                    }
                    continue;
                }
                Ok(ToHelper::Shutdown) => std::process::exit(EXIT_PIPE_CLOSED),
                Ok(ToHelper::Reply { seq, results }) => Work::Reply { seq, results },
                Ok(message) => Work::Message(message),
                Err(_) => std::process::exit(EXIT_BAD_FRAME),
            };
            if tx.send(work).is_err() {
                std::process::exit(EXIT_PIPE_CLOSED);
            }
        }
    });
    rx
}
