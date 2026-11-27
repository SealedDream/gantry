//! Journeys 2/11/15: public library and palette calls; timings exclude fixture creation.
//! These are backend timings, not rendered-UI latency measurements.
use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_ffi::{Library, PaletteEntryInput, PaletteIndex};
use std::time::Instant;

#[test]
fn library_and_palette_preserve_all_hosts_at_5000_and_20000_items() {
    let mut slowest_tree_ms = 0.0_f64;
    let counts = match std::env::var("BASTION_QA_ITEMS").as_deref() {
        Ok("5000") => vec![5_000],
        Ok("20000") => vec![20_000],
        Err(std::env::VarError::NotPresent) => vec![5_000, 20_000],
        _ => panic!("BASTION_QA_ITEMS must be 5000 or 20000, or unset for both"),
    };
    for count in counts {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.json");
        let mut doc = Document::new("Generated QA inventory");
        doc.root.children = (0..count)
            .map(|i| {
                Node::Connection(Connection::new(
                    format!("qa-host-{i:05}"),
                    Protocol::Ssh,
                    "127.0.0.1",
                ))
            })
            .collect();
        std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
        let start = Instant::now();
        let lib = Library::open(path.to_str().unwrap().into()).unwrap();
        let open_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let tree = lib.tree();
        let tree_ms = start.elapsed().as_secs_f64() * 1000.0;
        slowest_tree_ms = slowest_tree_ms.max(tree_ms);
        assert_eq!(tree.connections.len(), count);
        let entries = lib.palette_connections().unwrap();
        assert_eq!(entries.len(), count);
        let index = PaletteIndex::new(
            entries
                .into_iter()
                .map(|e| PaletteEntryInput {
                    kind: "connection".into(),
                    title: e.title,
                    detail: e.detail,
                    keywords: e.keywords,
                })
                .collect(),
        )
        .unwrap();
        let mut timings = Vec::new();
        for i in 0..25 {
            let wanted = (count / 25) * i;
            let start = Instant::now();
            let hits = index.rank(format!("qa-host-{wanted:05}"), 30);
            timings.push(start.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(hits, [wanted as u32]);
        }
        timings.sort_by(f64::total_cmp);
        eprintln!("QA_PERF items={count} ffi_open_ms={open_ms:.3} ffi_tree_ms={tree_ms:.3} palette_rank_p50_ms={:.3} palette_rank_p95_ms={:.3}", timings[12], timings[23]);
    }
    // Tree construction is only one part of launch. Exceeding the documented 1,000 ms cold
    // launch budget here already makes that budget impossible for this generated inventory.
    // Debug measurements are diagnostic; enforce this necessary condition only when optimized.
    if !cfg!(debug_assertions) {
        assert!(
            slowest_tree_ms <= 1_000.0,
            "Q09: library tree alone took {slowest_tree_ms:.3} ms (cold launch budget: 1000 ms)"
        );
    }
}
