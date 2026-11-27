//! Builds the IronRDP connector configuration from a target. Only settings the adapter
//! actually honours are taken from the target; the rest are fixed, conservative defaults.
use ironrdp_connector::{BitmapConfig, Config, Credentials, DesktopSize};
use ironrdp_pdu::rdp::capability_sets::BitmapCodecs;
use ironrdp_pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp_pdu::rdp::capability_sets::{MajorPlatformType, RailSupportLevel};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

use crate::RdpTarget;

/// RDP desktops must be at least this big, and at most 8192 on each side.
const MIN_SIDE: u16 = 200;
const MAX_SIDE: u16 = 8192;

pub fn clamp_side(v: u16) -> u16 {
    v.clamp(MIN_SIDE, MAX_SIDE)
}

/// Colour depths RDP bitmap updates support; anything else falls back to 32.
fn color_depth(v: u32) -> u32 {
    if matches!(v, 15 | 16 | 24 | 32) { v } else { 32 }
}

/// Largest RGBA framebuffer a server may make us allocate (8192 x 8192 x 4 bytes).
pub const MAX_FRAME_BYTES: usize = MAX_SIDE as usize * MAX_SIDE as usize * 4;

/// Validate a server-negotiated desktop size before allocating its framebuffer: nonzero, at most
/// `MAX_SIDE` per side and within `MAX_FRAME_BYTES`. A server cannot bypass the request bound.
pub fn checked_desktop(width: u16, height: u16) -> Result<(u16, u16), String> {
    let bytes = (width as usize).checked_mul(height as usize).and_then(|p| p.checked_mul(4));
    match bytes {
        Some(b) if width > 0 && height > 0 && width <= MAX_SIDE && height <= MAX_SIDE && b <= MAX_FRAME_BYTES => Ok((width, height)),
        _ => Err(format!("the server asked for an unsupported desktop size {width}x{height}")),
    }
}

pub fn build(target: &RdpTarget, password: String) -> Config {
    Config {
        desktop_size: DesktopSize { width: clamp_side(target.width), height: clamp_side(target.height) },
        monitor_layout: None,
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        // NLA only: request HYBRID (CredSSP) alone, so negotiation fails instead of falling back to TLS.
        enable_tls: !target.nla_only,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        credentials: Credentials::UsernamePassword { username: target.username.clone(), password },
        domain: target.domain.clone().filter(|d| !d.is_empty()),
        client_build: 0,
        client_name: "Gantry".into(),
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_functional_keys_count: 12,
        keyboard_layout: 0,
        connection_type: ConnectionType::Lan,
        ime_file_name: String::new(),
        bitmap: (color_depth(target.color_depth) != 32).then(|| BitmapConfig { lossy_compression: false, color_depth: color_depth(target.color_depth), codecs: BitmapCodecs(Vec::new()) }),
        dig_product_id: String::new(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".into(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: RailSupportLevel::empty(),
        platform: if cfg!(windows) { MajorPlatformType::WINDOWS } else { MajorPlatformType::MACINTOSH },
        hardware_id: None,
        request_data: None,
        // Log on with the supplied credentials instead of showing the server's own login screen (xrdp honours it).
        autologon: true,
        enable_audio_playback: target.audio,
        enable_audio_capture: false,
        performance_flags: PerformanceFlags::default(),
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: true,
        multitransport_flags: None,
        // Advertise the graphics pipeline (EGFX); Windows then sends H.264 or RemoteFX instead of legacy bitmaps.
        support_dyn_vc_gfx_protocol: true,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn negotiated_desktop_size_is_bounded() {
        assert_eq!(super::checked_desktop(1920, 1080), Ok((1920, 1080)));
        assert_eq!(super::checked_desktop(8192, 8192), Ok((8192, 8192)));
        for (w, h) in [(65535, 65535), (0, 600), (800, 0), (8193, 100)] {
            assert!(super::checked_desktop(w, h).is_err(), "{w}x{h}");
        }
    }

    use super::*;

    fn target(nla_only: bool) -> RdpTarget {
        RdpTarget { host: "h".into(), port: 3389, username: "u".into(), domain: None, width: 1280, height: 800, trusted_fingerprint: None, nla_only, via_loopback_port: None, clipboard: false, shared_folder: None, audio: false, color_depth: 32 }
    }

    #[test]
    fn nla_only_requests_credssp_without_a_tls_fallback() {
        let c = build(&target(true), String::new());
        assert!(c.enable_credssp && !c.enable_tls && !c.enable_standard_rdp_security);
        let c = build(&target(false), String::new());
        assert!(c.enable_credssp && c.enable_tls && !c.enable_standard_rdp_security);
    }

    #[test]
    fn desktop_size_is_clamped_to_protocol_limits() {
        assert_eq!(clamp_side(0), MIN_SIDE);
        assert_eq!(clamp_side(1280), 1280);
        assert_eq!(clamp_side(u16::MAX), MAX_SIDE);
    }
}
