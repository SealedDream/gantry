//! Ansible through the C ABI (90): inventory export from a library, then run plans that refuse
//! anything that could become an option.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::{json, Value};

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn plan(input: Value) -> Result<Value, String> {
    let mut err = null_mut();
    let r = bastion_ansible_run_plan_json(c(&input.to_string()).as_ptr(), &mut err);
    if r.is_null() { Err(take(err)) } else { Ok(serde_json::from_str(&take(r)).unwrap()) }
}

#[test]
fn export_an_inventory_and_plan_runs_against_it() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        for (name, host) in [("web1", "10.0.0.1"), ("bad name", "10.0.0.2")] {
            take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c("ssh").as_ptr(), c(host).as_ptr(), 2222, c("ops").as_ptr(), &mut err));
        }
        let inv = d.path().join("inventory.ini");
        let r: Value = serde_json::from_str(&take(bastion_library_export_ansible_inventory_json(lib, c(inv.to_str().unwrap()).as_ptr(), null(), 0, &mut err))).unwrap();
        assert_eq!(r["exported"], 1, "{r}");
        assert!(r["skipped"][0].as_str().unwrap().starts_with("bad name"), "{r}");
        let text = std::fs::read_to_string(&inv).unwrap();
        assert!(text.contains("web1 ansible_host=10.0.0.1") && text.contains("ansible_port=2222") && text.contains("ansible_user=ops"), "{text}");
        let yml = d.path().join("inventory.yml");
        take(bastion_library_export_ansible_inventory_json(lib, c(yml.to_str().unwrap()).as_ptr(), null(), 1, &mut err));
        assert!(std::fs::read_to_string(&yml).unwrap().contains("web1:"));
        bastion_library_free(lib);

        let inv_s = inv.to_str().unwrap();
        let p = plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "bastion", "module": "ansible.builtin.shell", "moduleArgs": "uptime", "check": true})).unwrap();
        assert_eq!(p["argv"], json!(["ansible", "bastion", "-i", inv_s, "-m", "ansible.builtin.shell", "-a", "uptime", "--check"]));
        assert_eq!(p["warnings"].as_array().unwrap().len(), 1, "shell module is pointed out");
        let pb = d.path().join("site.yml");
        std::fs::write(&pb, "- hosts: all\n  tasks: []\n").unwrap();
        let p = plan(json!({"kind": "playbook", "inventory": inv_s, "playbook": pb.to_str().unwrap(), "limit": "web1", "become": true, "forks": 5, "verbosity": 1})).unwrap();
        assert_eq!(p["argv"], json!(["ansible-playbook", "-i", inv_s, pb.to_str().unwrap(), "--limit", "web1", "--become", "--forks", "5", "-v"]));

        for bad in [
            json!({"kind": "adhoc", "inventory": inv_s, "pattern": "-e", "module": "ping"}),
            json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping x"}),
            json!({"kind": "adhoc", "inventory": "relative.ini", "pattern": "all", "module": "ping"}),
            json!({"kind": "playbook", "inventory": inv_s, "playbook": inv_s}),
            json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping", "forks": 0}),
            json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping", "verbosity": 9}),
            json!({"kind": "shell", "inventory": inv_s}),
        ] {
            assert!(plan(bad.clone()).is_err(), "{bad}");
        }

        // A control-host run: same checks, plus where everything goes on the host.
        let p = plan(json!({"kind": "playbook", "inventory": inv_s, "playbook": pb.to_str().unwrap(), "check": true, "tags": "web", "extraVars": "env=lab",
            "remote": {"home": "/home/ops", "runId": "00ff00ff", "uploadFolder": false}})).unwrap();
        let dir = "/home/ops/.gantry-ansible-00ff00ff";
        assert_eq!(p["remote"]["dir"], dir);
        assert_eq!(p["remote"]["argv"], json!(["ansible-playbook", "-i", format!("{dir}/inventory.ini"), format!("{dir}/site.yml"), "--check", "--tags", "web", "-e", "env=lab"]));
        assert_eq!(p["remote"]["uploads"][1], json!({"local": pb.to_str().unwrap(), "remote": format!("{dir}/site.yml")}));
        assert!(p["remote"]["command"].as_str().unwrap().contains("rm -rf --"));
        assert!(plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping", "remote": {"home": "~", "runId": "00ff00ff"}})).is_err());
        assert!(plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping"})).unwrap()["remote"].is_null());
        // Save as Task: the task for each mode, without a new export.
        let t = plan(json!({"kind": "playbook", "inventory": inv_s, "playbook": pb.to_str().unwrap(), "task": {"mode": "host", "hostName": "ctl"}})).unwrap();
        assert_eq!(t["task"]["runOn"], "ssh");
        assert_eq!(t["task"]["program"], "sh");
        assert_eq!(t["task"]["name"], "Ansible site.yml on ctl");
        let w = plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping", "task": {"mode": "wsl"}})).unwrap();
        assert_eq!((w["task"]["program"].as_str(), w["task"]["runOn"].as_str()), (Some("wsl.exe"), Some("local")));
        assert!(plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping", "task": {"mode": "nope"}})).is_err());
        assert!(plan(json!({"kind": "adhoc", "inventory": inv_s, "pattern": "all", "module": "ping"})).unwrap()["task"].is_null());
    }
}
