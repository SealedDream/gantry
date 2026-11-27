//! Library-size benchmarks for the core-health findings H02, H03, H04 and H06.
//! `cargo run --release --example health_bench [N]` (default 5000 and 20000 connections).
//! Prints wall time per operation; compare before/after a change on the same machine.
use std::time::Instant;

use bastion_core::model::{Connection, Document, Folder, Node, Protocol};
use bastion_core::sshconfig::ResolvedHost;
use bastion_core::{properties, search, sshworkflow};
use uuid::Uuid;

const GROUPS: usize = 50;
const RESOLVE_SAMPLES: usize = 200;

fn host(i: usize) -> ResolvedHost {
    ResolvedHost {
        alias: format!("host-{i}"),
        identity: format!("id-{i}"),
        source_file: format!("config.d/g{}", i % GROUPS),
        group: format!("g{}", i % GROUPS),
        hostname: format!("10.0.{}.{}", i / 250, i % 250),
        ..Default::default()
    }
}

fn library(n: usize) -> (Document, Vec<ResolvedHost>) {
    let mut doc = Document::new("bench");
    let hosts: Vec<ResolvedHost> = (0..n).map(host).collect();
    sshworkflow::import_hosts(&mut doc, &hosts).expect("import");
    // A flat folder of plain connections too, so H02's preview has a large qualifying set.
    let mut flat = Folder { id: Uuid::new_v4(), name: "flat".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
    for i in 0..n / 4 {
        let mut c = Connection::new(format!("flat-{i}"), Protocol::Ssh, format!("flat{i}.example"));
        c.tags = vec!["prod".into(), "web".into()];
        flat.children.push(Node::Connection(c));
    }
    doc.insert(None, Node::Folder(flat)).expect("insert");
    (doc, hosts)
}

fn time<T>(label: &str, n: usize, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let out = f();
    println!("{label:<34} n={n:<6} {:>10.2} ms", t.elapsed().as_secs_f64() * 1000.0);
    out
}

fn run(n: usize) {
    let (doc, hosts) = library(n);
    let ids: Vec<Uuid> = doc.connections().iter().step_by((n / RESOLVE_SAMPLES).max(1)).map(|r| r.connection.id).take(RESOLVE_SAMPLES).collect();

    let hits = time("H02 affected_by (root default)", n, || properties::affected_by(&doc, None, None, "keepalive_secs"));
    assert!(!hits.is_empty());
    time(&format!("H04 resolve x{}", ids.len()), n, || {
        for id in &ids {
            doc.resolve(*id).expect("resolve");
        }
    });
    let found = time("H06 search 'g7 host-1' x20", n, || (0..20).map(|_| search::search(&doc, "g7 host-1").len()).sum::<usize>());
    assert!(found > 0);
    let mut d = doc.clone();
    time("H03 reimport_hosts (all existing)", n, || sshworkflow::reimport_hosts(&mut d, &hosts).expect("reimport"));
}

fn main() {
    let sizes: Vec<usize> = match std::env::args().nth(1) {
        Some(a) => vec![a.parse().expect("N")],
        None => vec![5_000, 20_000],
    };
    for n in sizes {
        run(n);
    }
}
