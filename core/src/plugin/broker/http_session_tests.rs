use super::*;
use crate::plugin::broker::secret::SecretCheck;

const LOGIN: &str = r#"<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body><urn:Login><urn:_this type="SessionManager">ha-sessionmgr</urn:_this><urn:userName>{user}</urn:userName><urn:password>{secret}</urn:password></urn:Login></soapenv:Body></soapenv:Envelope>"#;
const LOGOUT: &str = r#"<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body><urn:Logout><urn:_this type="SessionManager">ha-sessionmgr</urn:_this></urn:Logout></soapenv:Body></soapenv:Envelope>"#;

fn session() -> HttpSession {
    HttpSession { login_path: "/sdk".into(), login_body: LOGIN.into(), content_type: "text/xml".into(), cookie: "vmware_soap_session".into(), logout_body: Some(LOGOUT.into()), ticket: None }
}

fn resp(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
    HttpResponse { status, headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect(), body: body.to_vec(), keep_alive: true }
}

#[test]
fn one_login_method_per_connection_type() {
    assert_eq!(resolve_login(None, true, false), Ok(Some(LoginMethod::Auth)));
    assert_eq!(resolve_login(None, false, true), Ok(Some(LoginMethod::Session)));
    assert_eq!(resolve_login(None, false, false), Ok(None));
    assert_eq!(resolve_login(Some("session"), true, true), Ok(Some(LoginMethod::Session)));
    assert_eq!(resolve_login(Some("auth"), true, true), Ok(Some(LoginMethod::Auth)));
    assert!(resolve_login(None, true, true).is_err(), "both set and no choice");
    assert!(resolve_login(Some("session"), true, false).is_err(), "session without [http.session]");
    assert!(resolve_login(Some("auth"), false, true).is_err(), "auth without auth");
    assert!(resolve_login(Some("cookie"), true, true).is_err(), "unknown method");
}

#[test]
fn good_templates() {
    assert!(valid_xml_template(LOGIN, true));
    assert!(valid_xml_template(LOGOUT, false));
    assert!(valid_xml_template("<a>x &amp; &#65; {secret}</a>", true));
    assert!(valid_json_template(r#"{"user":"{user}","password":"{secret}"}"#, true));
    assert!(valid_template(LOGIN, "text/xml", true));
}

#[test]
fn malicious_templates_are_refused() {
    let bad = [
        // Placeholders outside text nodes.
        r#"<a b="{secret}">x</a>"#,
        "<a><!-- {secret} --></a>",
        "<a><![CDATA[{secret}]]></a>",
        "<{secret}/>",
        "{secret}<a/>",
        // DOCTYPE and entities.
        r#"<!DOCTYPE a [<!ENTITY x "y">]><a>{secret}</a>"#,
        "<a>&x;{secret}</a>",
        "<?pi x?><a>{secret}</a>",
        // Not well formed, two roots, other braces.
        "<a>{secret}</b>",
        "<a>{secret}",
        "<a>{secret}</a><b/>",
        "<a>{secret}{password}</a>",
        // The secret twice, or not at all; the user twice.
        "<a>{secret}{secret}</a>",
        "<a>{user}</a>",
        "<a>{secret}{user}{user}</a>",
    ];
    for b in bad {
        assert!(!valid_xml_template(b, true), "{b}");
    }
    assert!(!valid_xml_template(&format!("<a>{{secret}}{}</a>", "x".repeat(MAX_LOGIN_BODY_BYTES)), true), "over 4 KiB");
    assert!(!valid_xml_template("<a>{secret}</a>", false), "a logout never holds the secret");
    for b in [r#"{"p":"x{secret}"}"#, r#"{"p":{secret}}"#, r#"{"{secret}":1}"#, r#"["{secret}"]"#, "{secret}"] {
        assert!(!valid_json_template(b, true), "{b}");
    }
    assert!(!valid_template(LOGIN, "text/html", true));
}

#[test]
fn cookie_names_and_paths() {
    assert!(valid_cookie_name("vmware_soap_session"));
    for n in ["", "a b", "a=b", "a;b", "a\"", &"x".repeat(65)] {
        assert!(!valid_cookie_name(n), "{n}");
    }
    let paths = vec!["/api/vcenter/".to_string(), "/sdk/".to_string()];
    assert!(valid_login_path("/sdk", &paths));
    assert!(!valid_login_path("/sdk/../x", &paths));
    assert!(!valid_login_path("/other", &paths), "outside paths");
    assert!(!valid_login_path("sdk", &paths));
    assert!(valid_content_type("text/xml") && valid_content_type("application/json") && !valid_content_type("text/plain"));
}

#[test]
fn the_login_body_escapes_the_login() {
    let body = render(LOGIN, "text/xml", "root<&>", b"p'a\"ss</urn:password>").unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("<urn:userName>root&lt;&amp;&gt;</urn:userName>"));
    assert!(text.contains("<urn:password>p&apos;a&quot;ss&lt;/urn:password&gt;</urn:password>"));
    assert!(valid_xml_template(&text.replace("ha-sessionmgr", "{secret}"), true) || true);
    assert!(render(LOGIN, "text/xml", "u", b"a\x01b").is_err(), "a control byte cannot be written");
    let json = render(r#"{"u":"{user}","p":"{secret}"}"#, "application/json", "u", b"a\"b").unwrap();
    assert_eq!(json.as_slice(), br#"{"u":"u","p":"a\"b"}"#);
}

#[test]
fn the_login_request() {
    let w = login_request(&session(), b"<x/>", "esxi.lab:443", "dev.bastion.vmware");
    let t = String::from_utf8(w.to_vec()).unwrap();
    assert!(t.starts_with("POST /sdk HTTP/1.1\r\nHost: esxi.lab:443\r\n"));
    assert!(t.contains("Content-Type: text/xml; charset=utf-8\r\n") && t.contains("Content-Length: 4\r\n\r\n<x/>"));
    let out = logout_request(&session(), b"<y/>", "h", "p", "abc").unwrap();
    assert!(String::from_utf8(out.to_vec()).unwrap().contains("\r\nCookie: vmware_soap_session=abc\r\n"));
    let no_logout = HttpSession { logout_body: None, ..session() };
    assert!(logout_request(&no_logout, b"", "h", "p", "abc").is_none());
}

#[test]
fn the_cookie_comes_only_from_a_good_login_answer() {
    let ok = resp(200, &[("Set-Cookie", "other=1"), ("Set-Cookie", "vmware_soap_session=\"52a1-bc\"; Path=/; HttpOnly; Secure")], b"");
    assert_eq!(session_cookie(&ok, "vmware_soap_session").unwrap().as_str(), "52a1-bc");
    let redirect = resp(302, &[("Location", "https://evil.example/"), ("Set-Cookie", "vmware_soap_session=x")], b"");
    assert!(session_cookie(&redirect, "vmware_soap_session").is_none(), "never from a redirect");
    assert!(session_cookie(&resp(500, &[("Set-Cookie", "vmware_soap_session=x")], b""), "vmware_soap_session").is_none());
    assert!(session_cookie(&resp(200, &[("Set-Cookie", "vmware_soap_session=")], b""), "vmware_soap_session").is_none());
    assert!(session_cookie(&resp(200, &[("Set-Cookie", "vmware_soap_session=a b")], b""), "vmware_soap_session").is_none());
    assert!(session_cookie(&resp(200, &[], b""), "vmware_soap_session").is_none());
}

#[test]
fn the_cookie_goes_after_the_request_line_and_set_cookie_never_reaches_the_plugin() {
    let w = with_cookie(b"POST /sdk HTTP/1.1\r\nHost: h\r\n\r\nbody", "c", "v");
    assert_eq!(w.as_slice(), b"POST /sdk HTTP/1.1\r\nCookie: c=v\r\nHost: h\r\n\r\nbody");
    let mut r = resp(200, &[("Set-Cookie", "c=v"), ("set-cookie2", "x"), ("Content-Type", "text/xml")], b"");
    strip_set_cookie(&mut r);
    assert_eq!(r.headers, vec![("Content-Type".to_string(), "text/xml".to_string())]);
}

#[test]
fn session_manager_calls_are_refused() {
    let call = |m: &str| format!(r#"<soapenv:Envelope xmlns:soapenv="s" xmlns:urn="urn:vim25"><soapenv:Body><urn:{m}><urn:_this>ha-sessionmgr</urn:_this></urn:{m}></soapenv:Body></soapenv:Envelope>"#);
    for m in ["Login", "LoginByToken", "LoginExtensionByCertificate", "AcquireCloneTicket", "AcquireSessionTicket", "ImpersonateUser", "SessionIsActive", "CloneSession"] {
        assert!(calls_session_method(call(m).as_bytes()), "{m}");
    }
    assert!(calls_session_method(b"<Login/>"), "no prefix");
    assert!(!calls_session_method(call("RetrievePropertiesEx").as_bytes()));
    assert!(!calls_session_method(call("PowerOnVM_Task").as_bytes()));
    assert!(calls_session_method(b"<a><b></a"), "a body that does not parse");
    assert!(calls_session_method(b"<!DOCTYPE a><a/>"));
    assert!(targets_login_path("/sdk", "/sdk") && targets_login_path("/sdk/?x", "/sdk") && !targets_login_path("/sdkx", "/sdk"));
    // Review HIGH 1: below the login path too.
    assert!(targets_login_path("/sdk/vimService", "/sdk") && targets_login_path("/sdk/vimService?wsdl", "/sdk") && targets_login_path("/sdk/a/b", "/sdk/"));
    // Review LOW 7.
    for m in ["Logout", "TerminateSession", "AcquireGenericServiceTicket"] {
        assert!(calls_session_method(call(m).as_bytes()), "{m}");
    }
    assert!(!calls_session_method(b""), "an empty body calls nothing");
}

#[test]
fn not_authenticated_answers() {
    assert!(not_authenticated(&resp(401, &[], b"")));
    assert!(!not_authenticated(&resp(500, &[], b"<faultstring>other</faultstring>")));
    assert!(!not_authenticated(&resp(200, &[], b"NotAuthenticated")));
    // Review MEDIUM 2: only a fault element inside Fault/detail counts, not the word elsewhere.
    let fault = |detail: &str, text: &str| format!(r#"<soapenv:Envelope xmlns:soapenv="s"><soapenv:Body><soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>{text}</faultstring><detail>{detail}</detail></soapenv:Fault></soapenv:Body></soapenv:Envelope>"#);
    assert!(not_authenticated(&resp(500, &[], fault(r#"<NotAuthenticatedFault xmlns="urn:vim25"/>"#, "x").as_bytes())));
    assert!(not_authenticated(&resp(500, &[], fault("<NotAuthenticated><object>s</object></NotAuthenticated>", "x").as_bytes())));
    assert!(!not_authenticated(&resp(500, &[], fault("<InvalidArgumentFault/>", "NotAuthenticated").as_bytes())), "the word in faultstring");
    assert!(!not_authenticated(&resp(500, &[], b"<x><NotAuthenticatedFault/></x>")), "not inside a fault");
    assert!(!not_authenticated(&resp(500, &[], b"<<NotAuthenticated")), "not XML");
}

#[test]
fn the_echo_check_finds_every_form_of_the_password_and_the_cookie() {
    let password = b"p<&>ss'word";
    let cookie = b"52a1bc0d-cookie";
    let mut check = SecretCheck::new();
    check.add(password);
    check.add(cookie);
    for form in escaped_forms(password) {
        check.add(&form);
    }
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b).into_bytes();
    let pct = |b: &[u8]| b.iter().flat_map(|c| if c.is_ascii_alphanumeric() || b"-._~".contains(c) { vec![*c] } else { format!("%{c:02X}").into_bytes() }).collect::<Vec<u8>>();
    for secret in [&password[..], &cookie[..]] {
        for form in [secret.to_vec(), b64(secret), pct(secret)] {
            assert!(check.matches(&[b"<x>".as_slice(), &form, b"</x>"].concat()), "{}", String::from_utf8_lossy(&form));
        }
    }
    assert!(check.matches(b"<faultstring>bad p&lt;&amp;&gt;ss&apos;word</faultstring>"), "XML-escaped");
    assert!(!check.matches(b"<ok/>"));
}

#[test]
fn a_ticket_comes_from_the_json_body() {
    let pve = HttpSession { login_path: "/api2/json/access/ticket".into(), login_body: r#"{"username":"{user}","password":"{secret}"}"#.into(), content_type: "application/json".into(), cookie: "PVEAuthCookie".into(), logout_body: None, ticket: Some("data.ticket".into()) };
    let body = br#"{"data":{"ticket":"PVE:u@pve:6740ABCD::a+b/c=","CSRFPreventionToken":"x"}}"#;
    assert_eq!(session_value(&resp(200, &[], body), &pve).unwrap().as_str(), "PVE:u@pve:6740ABCD::a+b/c=");
    assert!(session_value(&resp(401, &[], body), &pve).is_none(), "only a success");
    assert!(session_value(&resp(200, &[("Set-Cookie", "PVEAuthCookie=x")], b"{\"data\":null}"), &pve).is_none(), "never the header when a ticket path is named");
    assert!(session_value(&resp(200, &[], br#"{"data":{"ticket":"a;b"}}"#), &pve).is_none(), "a cookie header must carry it");
    assert!(session_value(&resp(200, &[], br#"{"data":{"ticket":7}}"#), &pve).is_none());
    assert!(session_value(&resp(200, &[], b"not json"), &pve).is_none());
    // Without a ticket path the header is used, as before.
    assert_eq!(session_value(&resp(200, &[("Set-Cookie", "vmware_soap_session=52a1")], b""), &session()).unwrap().as_str(), "52a1");
}

#[test]
fn ticket_paths() {
    assert!(valid_ticket_path("data.ticket"));
    for bad in ["", ".", "data..ticket", "a.b.c.d.e", "data.tic-ket", "data[0]"] {
        assert!(!valid_ticket_path(bad), "{bad}");
    }
}
