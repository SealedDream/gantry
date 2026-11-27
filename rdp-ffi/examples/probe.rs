//! Manual check against a real server: `cargo run --example probe -- <host> <port> <user> <out.ppm>`
//! with the password in `BASTION_RDP_PASSWORD`. Accepts the certificate on first use (test only).
//! `BASTION_RDP_SIZE=1920x1080` sets the desktop size; `BASTION_RDP_MEASURE=<secs>` then polls
//! Channels: `BASTION_RDP_CLIPBOARD=<text>` shares the clipboard and offers that text,
//! `BASTION_RDP_SHARE=<folder>` shares a folder, `BASTION_RDP_AUDIO=1` plays sound, and
//! `BASTION_RDP_HOLD=<secs>` keeps the session up, printing text copied on the server and audio bytes.
//! `BASTION_OPENH264_DIR=<folder>` downloads Cisco's OpenH264 there and offers H.264 (`RUST_LOG=ironrdp_egfx=debug`
//! logs `EGFX capabilities confirmed avc420=true`).
//! `frame_update` at 120 Hz (set `RUST_LOG=warn` to see IRONRDP decode problems) and prints updates/s, dirty bytes/s and process CPU time.
use bastion_rdp::{RdpError, RdpSession, RdpState, RdpTarget};

fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    let args: Vec<String> = std::env::args().collect();
    let password = std::env::var("BASTION_RDP_PASSWORD").expect("BASTION_RDP_PASSWORD");
    let mut target = RdpTarget {
        host: args[1].clone(),
        port: args[2].parse().unwrap(),
        username: args[3].clone(),
        domain: None,
        width: size().0,
        height: size().1,
        trusted_fingerprint: None,
        nla_only: std::env::var("BASTION_RDP_NLA_ONLY").is_ok(),
        via_loopback_port: std::env::var("BASTION_RDP_VIA_PORT").ok().and_then(|p| p.parse().ok()),
        clipboard: std::env::var("BASTION_RDP_CLIPBOARD").is_ok(),
        shared_folder: std::env::var("BASTION_RDP_SHARE").ok(),
        audio: std::env::var("BASTION_RDP_AUDIO").is_ok(),
        color_depth: 32,
    };
    if let Ok(dir) = std::env::var("BASTION_OPENH264_DIR") {
        let path = bastion_rdp::openh264::install(std::path::Path::new(&dir)).expect("OpenH264");
        bastion_rdp::set_openh264_library_path(Some(path.to_string_lossy().into_owned()));
        println!("OpenH264: {}", path.display());
    }
    let session = RdpSession::new().unwrap();
    match session.connect(target.clone(), password.clone()) {
        Err(RdpError::CertificateUnknown { fingerprint }) => {
            println!("first connect: certificate unknown {fingerprint}");
            target.trusted_fingerprint = Some(fingerprint);
            session.connect(target, password).expect("pinned connect");
        }
        other => panic!("expected an unknown certificate first, got {other:?}"),
    }
    // RDP-VNC-FIT: a resize sent at once, before Display Control opens, must still apply.
    let resize = std::env::var("BASTION_RDP_RESIZE").ok().and_then(|v| v.split_once('x').map(|(w, h)| (w.parse::<u32>().unwrap(), h.parse::<u32>().unwrap())));
    if let Some((w, h)) = resize {
        session.resize(w, h);
        println!("resize {w}x{h} sent right after connect");
    }
    std::thread::sleep(std::time::Duration::from_secs(4));
    // `BASTION_RDP_RESIZE=WxH` asks for that size once the channels are open, as the Mac view does.
    if let Some((w, h)) = std::env::var("BASTION_RDP_RESIZE").ok().and_then(|v| v.split_once('x').map(|(w, h)| (w.parse().unwrap(), h.parse().unwrap()))) {
        session.resize(w, h);
        std::thread::sleep(std::time::Duration::from_secs(4));
    }
    assert_eq!(session.state(), RdpState::Connected, "{:?}", session.close_reason());
    if let Some((w, h)) = resize {
        // Windows opens Display Control only after logon: allow up to 20 s.
        let mut got = (0u32, 0u32);
        for _ in 0..80 {
            if let Some(f) = session.frame(0) { got = (f.width as u32, f.height as u32); }
            if got == (w & !1, h) { break; }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        println!("after resize: {}x{} ({})", got.0, got.1, if got == (w & !1, h) { "ok" } else { "NOT APPLIED" });
    }
    if let Ok(text) = std::env::var("BASTION_RDP_CLIPBOARD") {
        session.set_local_clipboard(text);
        println!("offered local clipboard");
    }
    if let Some(secs) = std::env::var("BASTION_RDP_HOLD").ok().and_then(|v| v.parse::<u64>().ok()) {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        while std::time::Instant::now() < end && session.state() == RdpState::Connected {
            if let Some(text) = session.take_remote_clipboard() {
                println!("remote clipboard: {text}");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        println!("audio bytes: {} state {:?} {:?}", session.audio_bytes(), session.state(), session.close_reason());
    }
    if let Some(secs) = std::env::var("BASTION_RDP_MEASURE").ok().and_then(|v| v.parse::<u64>().ok()) {
        measure(&session, secs);
    }
    let f = session.frame(0).expect("frame");
    let mut out = format!("P6 {} {} 255\n", f.width, f.height).into_bytes();
    for px in f.bgra.chunks_exact(4) {
        out.extend_from_slice(&[px[2], px[1], px[0]]);
    }
    std::fs::write(&args[4], out).unwrap();
    println!("connected {}x{} serial {}", f.width, f.height, f.serial);
    session.close();
    std::thread::sleep(std::time::Duration::from_millis(500));
    println!("after close: {:?} {:?}", session.state(), session.close_reason());
}

fn size() -> (u16, u16) {
    std::env::var("BASTION_RDP_SIZE")
        .ok()
        .and_then(|v| v.split_once('x').map(|(w, h)| (w.parse().unwrap(), h.parse().unwrap())))
        .unwrap_or((1024, 768))
}

fn cpu_seconds() -> f64 {
    let out = std::process::Command::new("ps").args(["-o", "cputime=", "-p", &std::process::id().to_string()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().split(':').fold(0.0, |acc, part| acc * 60.0 + part.parse::<f64>().unwrap_or(0.0))
}

/// Polls like a 120 Hz view would and reports what arrived; drag windows or play video meanwhile.
fn measure(session: &RdpSession, secs: u64) {
    let start = std::time::Instant::now();
    let cpu0 = cpu_seconds();
    let (mut serial, mut updates, mut fulls, mut bytes) = (0, 0u64, 0u64, 0u64);
    while start.elapsed().as_secs() < secs {
        if let Some(u) = session.frame_update(serial) {
            serial = u.serial;
            updates += 1;
            fulls += u64::from(u.full);
            bytes += u.rects.iter().map(|r| r.bgra.len() as u64).sum::<u64>();
        }
        std::thread::sleep(std::time::Duration::from_micros(8333));
    }
    let t = start.elapsed().as_secs_f64();
    println!(
        "measure {t:.1}s: {:.1} updates/s ({fulls} full), {:.1} MB/s dirty, {:.2} cores",
        updates as f64 / t,
        bytes as f64 / t / 1e6,
        (cpu_seconds() - cpu0) / t
    );
}
