//! Web sign-in autofill (B13, `docs/plans/B13-WEB-AUTOFILL.md`, threats T27.1–T27.12).
//!
//! The core decides whether a fill may happen; the apps only run the script this module builds.
//! A fill needs every one of: the policy does not forbid it, the connection's `web_autofill`
//! switch is on (off by default), the saved address and the page are https, the page loaded with
//! no certificate error and no insecure content, the request is for the top frame, and the page's
//! origin equals the saved address's origin exactly (scheme, host after IDNA, port). There is no
//! suffix, wildcard, "same site" or path match. The user's click on a native button is the only
//! trigger; nothing here runs on page load.
use url::Url;
use zeroize::Zeroizing;

/// Why a fill was refused. `reason()` is the text the app shows and the audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    PolicyForbids,
    Off,
    NotHttps,
    NotSecure,
    SubFrame,
    UserInfo,
    BadAddress,
    OriginMismatch { page: String, saved: String },
    NoCredential,
}

impl Refusal {
    /// A stable code for the audit log and the apps' tests.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::PolicyForbids => "policy",
            Refusal::Off => "off",
            Refusal::NotHttps => "not-https",
            Refusal::NotSecure => "not-secure",
            Refusal::SubFrame => "sub-frame",
            Refusal::UserInfo => "user-info",
            Refusal::BadAddress => "bad-address",
            Refusal::OriginMismatch { .. } => "origin-mismatch",
            Refusal::NoCredential => "no-credential",
        }
    }

    /// One line for the user.
    pub fn reason(&self) -> String {
        match self {
            Refusal::PolicyForbids => "Your administrator turned off sign-in fill.".into(),
            Refusal::Off => "Sign-in fill is off for this connection.".into(),
            Refusal::NotHttps => "Sign-in fill works only on https pages.".into(),
            Refusal::NotSecure => "Not filled: this page has insecure content.".into(),
            Refusal::SubFrame => "Not filled: the sign-in form is inside a frame.".into(),
            Refusal::UserInfo => "Not filled: the address carries a user name.".into(),
            Refusal::BadAddress => "Not filled: the address could not be read.".into(),
            Refusal::OriginMismatch { page, saved } => format!("Not filled: this page is {page}, the connection is {saved}."),
            Refusal::NoCredential => "No saved password for this connection.".into(),
        }
    }
}

/// The URL a web connection opens: `host` as saved when it has a scheme, else `https://host[:port]`.
pub fn saved_url(host: &str, port: Option<u16>) -> Option<Url> {
    let host = host.trim();
    let raw = if host.contains("://") { host.to_string() } else { format!("https://{host}{}", port.map(|p| format!(":{p}")).unwrap_or_default()) };
    Url::parse(&raw).ok()
}

/// `scheme://host:port`, lower case, host in IDNA ASCII form without a trailing dot, the port
/// always written. Refuses addresses with a user name or password and anything that is not https.
pub fn origin(url: &Url) -> Result<String, Refusal> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Refusal::UserInfo);
    }
    if url.scheme() != "https" {
        return Err(Refusal::NotHttps);
    }
    let host = url.host_str().ok_or(Refusal::BadAddress)?.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(Refusal::BadAddress);
    }
    let port = url.port_or_known_default().ok_or(Refusal::BadAddress)?;
    Ok(format!("https://{host}:{port}"))
}

/// The page's origin for the audit log: scheme, host and port only, never the path or query
/// (which can carry tokens). Empty when the address cannot be read.
pub fn audit_origin(page_url: &str) -> String {
    Url::parse(page_url.trim()).map(|u| u.origin().ascii_serialization()).unwrap_or_default()
}

/// What the app tells the core about the page at the moment of the click.
#[derive(Debug, Clone)]
pub struct PageState<'a> {
    pub url: &'a str,
    pub is_main_frame: bool,
    /// https, no certificate error, no insecure content.
    pub is_secure: bool,
}

/// The decision. `Ok` is the expected origin, which the fill script checks again inside the page.
pub fn check(policy_forbids: bool, switch_on: bool, saved: Option<&Url>, page: &PageState<'_>) -> Result<String, Refusal> {
    if policy_forbids {
        return Err(Refusal::PolicyForbids);
    }
    if !switch_on {
        return Err(Refusal::Off);
    }
    if !page.is_main_frame {
        return Err(Refusal::SubFrame);
    }
    let saved = origin(saved.ok_or(Refusal::BadAddress)?)?;
    let page_url = Url::parse(page.url.trim()).map_err(|_| Refusal::BadAddress)?;
    let page_origin = origin(&page_url)?;
    if !page.is_secure {
        return Err(Refusal::NotSecure);
    }
    if page_origin != saved {
        return Err(Refusal::OriginMismatch { page: page_origin, saved });
    }
    Ok(saved)
}

/// The script body: a function of (expected origin, user name, password). Its first statement
/// compares only unforgeable values (`window.top`, `location.origin`, `[LegacyUnforgeable]`)
/// with `!==`, before any call a page could have patched, so a page that took over between the
/// core's check and the run (WebView2 has no isolated world) cannot pass it. Only then does it
/// take the setter and helpers. It fills only visible, enabled, writable fields of the top
/// document, refuses two password fields, fires `input` and `change`, keeps nothing (no globals,
/// no attributes) and returns only a status word.
const FILL_FN: &str = r#"(function (expected, u, p) {
  if (window.top !== window || location.origin !== expected) return "origin-changed";
  const visible = (e) => {
    if (e.disabled || e.readOnly || e.type === "hidden") return false;
    const s = getComputedStyle(e);
    if (s.display === "none" || s.visibility === "hidden" || Number(s.opacity) === 0) return false;
    const r = e.getBoundingClientRect();
    return r.width >= 2 && r.height >= 2 && r.bottom > 0 && r.right > 0 && r.top < innerHeight && r.left < innerWidth;
  };
  const pw = Array.from(document.querySelectorAll("input[type=password]")).filter(visible);
  if (pw.length === 0) return "no-form";
  if (pw.length > 1) return "many-password-fields";
  const pass = pw[0];
  const scope = pass.form ? Array.from(pass.form.elements) : Array.from(document.querySelectorAll("input"));
  const before = scope.slice(0, scope.indexOf(pass)).filter((e) => e instanceof HTMLInputElement && /^(text|email|tel|)$/.test(e.type) && visible(e));
  const user = before.length ? before[before.length - 1] : null;
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const put = (e, v) => { set.call(e, v); e.dispatchEvent(new Event("input", { bubbles: true })); e.dispatchEvent(new Event("change", { bubbles: true })); };
  if (user) put(user, u);
  put(pass, p);
  return "filled";
})"#;

/// The saved address's origin as the page reports it in `location.origin` (default port left
/// out), for the in-page check.
pub fn script_origin(saved: &Url) -> String {
    saved.origin().ascii_serialization()
}

/// The script to run in the top frame: the function above called with three JSON string
/// literals (quotes, `<`, `>`, U+2028 and U+2029 escaped), built in one pass so no value is ever
/// substituted twice. The result holds the password and is wiped when dropped.
pub fn fill_script(script_origin: &str, username: &str, password: &str) -> Zeroizing<String> {
    let (o, u, p) = (js_string(script_origin), js_string(username), js_string(password));
    let mut out = Zeroizing::new(String::with_capacity(FILL_FN.len() + o.len() + u.len() + p.len() + 8));
    for part in [FILL_FN, "(", &o, ", ", &u, ", ", &p, ")"] {
        out.push_str(part);
    }
    out
}

/// A JSON string literal that is also safe inside an HTML script and in older JS engines.
fn js_string(s: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(s.len() + 2));
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> PageState<'_> {
        PageState { url, is_main_frame: true, is_secure: true }
    }

    fn decide(saved: &str, p: &PageState<'_>) -> Result<String, Refusal> {
        check(false, true, saved_url(saved, None).as_ref(), p)
    }

    #[test]
    fn exact_origin_passes_and_default_port_is_explicit() {
        assert_eq!(decide("https://admin.example.com/login", &page("https://admin.example.com/other?x=1")), Ok("https://admin.example.com:443".into()));
        assert_eq!(decide("admin.example.com", &page("https://ADMIN.example.com.:443/")), Ok("https://admin.example.com:443".into()));
    }

    #[test]
    fn look_alikes_are_refused() {
        for bad in [
            "https://admin.example.com.evil.net/",
            "https://evil-admin.example.com/",
            "https://example.com/",
            "https://admin.example.com:8443/",
            "https://аdmin.example.com/", // Cyrillic а
            "https://adm1n.example.com/",
        ] {
            assert!(matches!(decide("https://admin.example.com", &page(bad)), Err(Refusal::OriginMismatch { .. })), "{bad}");
        }
    }

    #[test]
    fn idn_hosts_compare_in_punycode() {
        let r = decide("https://bücher.example", &page("https://xn--bcher-kva.example/"));
        assert_eq!(r, Ok("https://xn--bcher-kva.example:443".into()));
        let Err(Refusal::OriginMismatch { page: p, .. }) = decide("https://admin.example.com", &page("https://аdmin.example.com/")) else { panic!() };
        assert!(p.starts_with("https://xn--"), "the refusal shows punycode: {p}");
    }

    #[test]
    fn every_condition_is_required() {
        let saved = saved_url("https://a.example", None);
        let ok = page("https://a.example/");
        assert_eq!(check(true, true, saved.as_ref(), &ok), Err(Refusal::PolicyForbids));
        assert_eq!(check(false, false, saved.as_ref(), &ok), Err(Refusal::Off));
        assert_eq!(check(false, true, saved.as_ref(), &PageState { is_main_frame: false, ..ok.clone() }), Err(Refusal::SubFrame));
        assert_eq!(check(false, true, saved.as_ref(), &PageState { is_secure: false, ..ok.clone() }), Err(Refusal::NotSecure));
        assert_eq!(check(false, true, saved.as_ref(), &page("http://a.example/")), Err(Refusal::NotHttps));
        assert_eq!(check(false, true, saved_url("http://a.example", None).as_ref(), &ok), Err(Refusal::NotHttps));
        assert_eq!(check(false, true, saved.as_ref(), &page("https://user:pw@a.example/")), Err(Refusal::UserInfo));
        assert_eq!(check(false, true, saved.as_ref(), &page("not a url")), Err(Refusal::BadAddress));
        assert_eq!(check(false, true, None, &ok), Err(Refusal::BadAddress));
    }

    #[test]
    fn script_values_are_json_literals() {
        let s = fill_script("https://a.example", "u\"ser", "p</script>\u{2028}'`${x}\\\n");
        assert!(s.contains(r#""u\"ser""#));
        assert!(s.contains(r#""p\u003c/script\u003e\u2028'`${x}\\\u000a""#), "{}", s.as_str());
        assert!(!s.contains("</script>"));
        assert!(s.starts_with("(function (expected, u, p) {\n  if (window.top !== window || location.origin !== expected)"));
        assert!(s.ends_with(r#"("https://a.example", "u\"ser", "p\u003c/script\u003e\u2028'`${x}\\\u000a")"#), "{}", s.as_str());
    }

    #[test]
    fn values_that_look_like_placeholders_are_substituted_once() {
        let s = fill_script("https://a.example", "__PASS__ u p expected", "__USER__");
        assert!(s.ends_with(r#"("https://a.example", "__PASS__ u p expected", "__USER__")"#), "{}", s.as_str());
    }

    #[test]
    fn script_origin_matches_location_origin() {
        assert_eq!(script_origin(&saved_url("https://Admin.Example.com:443/x", None).unwrap()), "https://admin.example.com");
        assert_eq!(script_origin(&saved_url("https://admin.example.com:8443/", None).unwrap()), "https://admin.example.com:8443");
        assert_eq!(script_origin(&saved_url("https://bücher.example", None).unwrap()), "https://xn--bcher-kva.example");
    }

    #[test]
    fn refusal_codes_are_stable_and_reasons_hold_no_secret() {
        let r = Refusal::OriginMismatch { page: "https://b:443".into(), saved: "https://a:443".into() };
        assert_eq!(r.code(), "origin-mismatch");
        assert!(r.reason().contains("https://b:443") && r.reason().contains("https://a:443"));
    }
}
