//! PLUG-03a baseline. Everything here uses only the API that existed before the tolerant
//! readers, so this one file also compiles in a worktree of the previous commit. The ignored
//! tests are run by hand from there (see docs/evidence/PLUG-03a.md):
//!
//! - `generate_golden` writes the bytes the previous app saves for a `VERSION` document;
//! - `previous_app_opens_and_saves_unchanged` opens files this branch saved at revision 2;
//! - `large_library_load_save_timing` prints load and save times for 5,000 connections.
use std::path::{Path, PathBuf};
use std::time::Instant;

use bastion_core::docfile::DocumentFile;
use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::store::Store;

const SOURCE: &str = include_str!("fixtures/plug03a/v1-source.json");

fn source() -> Document {
    serde_json::from_str(SOURCE).expect("the golden source parses")
}

fn env_dir(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| panic!("set {name} to a folder")))
}

/// What saving `bytes` (written at revision `from`) must produce: the same text, one revision on.
fn bumped(bytes: &[u8], from: u64) -> String {
    String::from_utf8(bytes.to_vec()).unwrap().replace(&format!("\"revision\": {from}"), &format!("\"revision\": {}", from + 1))
}

fn text(path: &Path) -> String {
    String::from_utf8(std::fs::read(path).unwrap()).unwrap()
}

fn save_document_once(dir: &Path) -> PathBuf {
    let path = dir.join("golden.bastion");
    DocumentFile::from_document(source()).save_as(&path).unwrap();
    path
}

fn save_library_once(dir: &Path) -> PathBuf {
    let path = dir.join("golden-library.json");
    Store::new(&path).save(&source()).unwrap();
    path
}

#[test]
#[ignore = "run by hand in a worktree of the previous commit; writes into PLUG03A_OUT"]
fn generate_golden() {
    let out = env_dir("PLUG03A_OUT");
    std::fs::create_dir_all(&out).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    std::fs::copy(save_document_once(tmp.path()), out.join("v1-golden.bastion")).unwrap();
    std::fs::copy(save_library_once(tmp.path()), out.join("v1-golden-library.json")).unwrap();
}

#[test]
#[ignore = "run by hand in a worktree of the previous commit; reads PLUG03A_IN"]
fn previous_app_opens_and_saves_unchanged() {
    let input = env_dir("PLUG03A_IN");
    let tmp = tempfile::tempdir().unwrap();

    let doc_path = tmp.path().join("saved.bastion");
    std::fs::copy(input.join("saved.bastion"), &doc_path).unwrap();
    let before = std::fs::read(&doc_path).unwrap();
    let mut d = DocumentFile::open(&doc_path).expect("the previous app opens the document");
    assert_eq!(d.document().unwrap().connections().len(), 7);
    d.document_mut().unwrap(); // mark dirty, change nothing
    d.save().unwrap();
    assert_eq!(text(&doc_path), bumped(&before, 2));

    let lib_path = tmp.path().join("saved-library.json");
    std::fs::copy(input.join("saved-library.json"), &lib_path).unwrap();
    let before = std::fs::read(&lib_path).unwrap();
    let store = Store::new(&lib_path);
    let loaded = store.load().expect("the previous app opens the library");
    assert_eq!(loaded.connections().len(), 7);
    store.save(&loaded).unwrap();
    assert_eq!(text(&lib_path), bumped(&before, 2));
}

fn large(connections_per_folder: usize) -> Document {
    let mut doc = Document::new("Big");
    for f in 0..50 {
        let id = uuid::Uuid::new_v4();
        let folder: Node = serde_json::from_value(serde_json::json!({ "kind": "folder", "id": id, "name": format!("F{f}") })).unwrap();
        doc.insert(None, folder).unwrap();
        for i in 0..connections_per_folder {
            let mut c = Connection::new(format!("h{f}-{i}"), if i % 3 == 0 { Protocol::Rdp } else { Protocol::Ssh }, format!("h{f}-{i}.lab.example"));
            c.settings.username = Some("ops".into());
            c.settings.port = Some(2200 + (i as u16 % 50));
            c.tags = vec!["lab".into()];
            c.metadata.insert("Group".into(), format!("g{f}"));
            doc.insert(Some(id), Node::Connection(c)).unwrap();
        }
    }
    doc
}

fn median_ms(mut f: impl FnMut()) -> f64 {
    let mut times: Vec<f64> = (0..61)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    times[times.len() / 2]
}

#[test]
#[ignore = "timing; run by hand with --release on a quiet Mac, before and after"]
fn large_library_load_save_timing() {
    let doc = large(100);
    assert_eq!(doc.connections().len(), 5000);
    let tmp = tempfile::tempdir().unwrap();

    let bytes = serde_json::to_vec_pretty(&doc).unwrap();
    let parse = median_ms(|| drop(serde_json::from_slice::<Document>(&bytes).unwrap()));
    let print = median_ms(|| drop(serde_json::to_vec_pretty(&doc).unwrap()));
    // The steps inside a document open, apart: bytes to a JSON tree, and the tree to a Document.
    let tree = median_ms(|| drop(serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let clone = median_ms(|| drop(value.clone()));
    let typed = median_ms(|| drop(serde_json::from_value::<Document>(value.clone()).unwrap())) - clone;

    let lib = tmp.path().join("library.json");
    let store = Store::new(&lib);
    store.save(&doc).unwrap();
    let store_load = median_ms(|| drop(store.load().unwrap()));
    let mut current = store.load().unwrap();
    let store_save = median_ms(|| current = store.save(&current).unwrap());

    let path = tmp.path().join("big.bastion");
    let mut file = DocumentFile::from_document(doc.clone());
    file.save_as(&path).unwrap();
    let doc_open = median_ms(|| drop(DocumentFile::open(&path).unwrap()));
    let doc_save = median_ms(|| {
        file.document_mut().unwrap();
        file.save().unwrap();
    });

    println!("PLUG03A-TIMING connections=5000 bytes={} median-of-61 ms: parse={parse:.2} print={print:.2} tree={tree:.2} typed_from_tree={typed:.2} store_load={store_load:.2} store_save={store_save:.2} document_open={doc_open:.2} document_save={doc_save:.2}", bytes.len());
}
