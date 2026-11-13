// SPDX-License-Identifier: Apache-2.0
//! Durability of investigations and graph states on a real database file: restart, crash during a
//! save (process abort and kill), failures inside the save transaction, locked database, full disk.
//!
//! Crash tests re-run this test binary as a child process (selected by an environment variable),
//! so a real process dies in the middle of a SQLite transaction.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use rusqlite::{params, Connection};
use serde_json::{json, Value};

use super::ingest::tests::{ent, ev, rel, run};
use super::ingest::Observation;
use super::model::EntityType;
use super::store::{self, GraphNodeState, GraphSave, InvestigationInput};
use crate::db::Db;
use crate::error::AppResult;

const CHILD_ENV: &str = "CYBERHUB_DURABILITY_CHILD";

fn temp_db(tag: &str) -> PathBuf {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).unwrap();
    let dir = std::env::temp_dir().join(format!("cyberhub-durability-{tag}-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("cyberhub.db")
}

fn cleanup(path: &Path) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

fn tx<T>(db: &Db, f: impl FnOnce(&Connection) -> AppResult<T>) -> AppResult<T> {
    db.with(|c| {
        let t = c.unchecked_transaction()?;
        let r = f(&t)?;
        t.commit()?;
        Ok(r)
    })
}

/// An investigation with a populated main graph. Returns (investigation, graph).
fn populate(db: &Db) -> (i64, i64) {
    let inv = tx(db, |c| {
        store::investigation_create(c, &InvestigationInput { name: "Durability".into(), description: String::new(), target_type: "domain".into(), target_value: "example.com".into(), tags: vec![], notes: String::new(), authorization: String::new(), project_id: None })
    })
    .unwrap();
    run(db, inv, &Observation {
        evidence: ev("dns", "records"),
        entities: vec![ent(EntityType::Domain, "example.com"), ent(EntityType::Ip, "93.184.216.34"), ent(EntityType::Domain, "www.example.com"), ent(EntityType::Organization, "Example Org")],
        relationships: vec![rel(0, 1, "RESOLVES_TO"), rel(2, 1, "RESOLVES_TO"), rel(0, 3, "REGISTERED_TO")],
    });
    let g = db.with(|c| Ok(store::graph_list(c, Some(inv))?[0].id)).unwrap();
    (inv, g)
}

/// A fully customised workspace: every property the UI persists.
fn custom_workspace(marker: i64) -> Value {
    json!({
        "version": 1,
        "layout": "manual",
        "labels": "always",
        "viewport": { "x": 12.5, "y": -40.25, "zoom": 1.75 },
        "filters": { "hiddenTypes": ["organization"], "hiddenVerifications": ["rejected", "inferred"], "hiddenRelationshipTypes": ["REGISTERED_TO"], "flaggedOnly": false },
        "groups": [{ "id": "g1", "label": "Hosts", "color": "#4c8dff" }],
        "focus": ["1"],
        "notes": "durability notes",
        "marker": marker
    })
}

fn custom_nodes(db: &Db, g: i64, x: f64) -> Vec<GraphNodeState> {
    let d = db.with(|c| store::graph_load(c, g, false)).unwrap();
    d.nodes
        .iter()
        .enumerate()
        .map(|(i, n)| GraphNodeState { entity_id: n.entity_id, x: Some(x + i as f64), y: Some(-x), pinned: i == 0, hidden: i == 1, group: (i == 2).then(|| "g1".to_string()) })
        .collect()
}

fn save(db: &Db, g: i64, nodes: Vec<GraphNodeState>, ws: Value) -> AppResult<store::SaveResult> {
    let d = db.with(|c| store::graph_load(c, g, false))?;
    tx(db, |c| store::graph_save(c, g, &GraphSave { base_revision: d.graph.revision, nodes, removed: vec![], workspace: ws, version_label: None, manual_version: false, base_state_revision: Some(d.graph.state_revision), force: false }))
}

/// Everything restoration depends on, for comparison.
fn state_of(db: &Db, g: i64) -> (Value, Vec<GraphNodeState>, i64, Vec<i64>) {
    let d = db.with(|c| store::graph_load(c, g, false)).unwrap();
    let versions: Vec<i64> = db.with(|c| store::versions(c, g)).unwrap().iter().map(|v| v.number).collect();
    (d.workspace, d.nodes, d.graph.state_revision, versions)
}

fn integrity(path: &Path) -> (String, usize) {
    let c = Connection::open(path).unwrap();
    let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    let fk = c.prepare("PRAGMA foreign_key_check").unwrap().query_map([], |_| Ok(())).unwrap().count();
    (ok, fk)
}

#[test]
fn every_saved_workspace_property_survives_a_restart() {
    let path = temp_db("restart");
    let (g, g_copy, g_restored, ops_before) = {
        let db = Db::open(&path).unwrap();
        let (inv, g) = populate(&db);
        save(&db, g, custom_nodes(&db, g, 100.0), custom_workspace(1)).unwrap();
        // Save As with different state, then a restored graph, then an interrupted collection
        // (node states are computed before the transaction: the connection mutex is not re-entrant)
        let copy_nodes = custom_nodes(&db, g, 500.0);
        let copy = tx(&db, |c| store::graph_save_as(c, g, "Copy", &copy_nodes, &custom_workspace(2), false)).unwrap();
        let restored = tx(&db, |c| store::graph_duplicate(c, g, "Restored")).unwrap();
        save(&db, restored, custom_nodes(&db, restored, 900.0), custom_workspace(3)).unwrap();
        // restore the duplicate's oldest version (its state when it was created)
        let oldest = db.with(|c| store::versions(c, restored)).unwrap().last().unwrap().id;
        tx(&db, |c| store::version_restore(c, oldest)).unwrap();
        db.with(|c| {
            c.execute("INSERT INTO osint_operations (investigation_id, provider, input_type, input_value, status, requested_by, started_at) VALUES (?1, 'dns', 'domain', 'example.com', 'running', 'analyst', '2026-01-01T00:00:00Z')", params![inv])?;
            Ok(())
        })
        .unwrap();
        (g, copy, restored, 1)
    };
    // remember what each graph looked like before the "restart"
    let before: Vec<_> = {
        let db = Db::open(&path).unwrap();
        [g, g_copy, g_restored].iter().map(|id| state_of(&db, *id)).collect()
    };
    // restart: a new process would open the file, run migrations and recover interrupted work
    let db = Db::open(&path).unwrap();
    super::discovery::recover_interrupted(&db);
    for (i, id) in [g, g_copy, g_restored].iter().enumerate() {
        assert_eq!(state_of(&db, *id), before[i], "graph {id} changed across the restart");
    }
    // the main graph: every property exactly as saved
    let (ws, nodes, _, _) = state_of(&db, g);
    assert_eq!(ws, custom_workspace(1));
    assert!(nodes.iter().all(|n| n.x.is_some() && n.y == Some(-100.0)));
    assert_eq!(nodes.iter().filter(|n| n.pinned).count(), 1);
    assert_eq!(nodes.iter().filter(|n| n.hidden).count(), 1);
    assert_eq!(nodes.iter().filter(|n| n.group.as_deref() == Some("g1")).count(), 1);
    // Save As kept its own state
    assert_eq!(state_of(&db, g_copy).0["marker"], 2);
    // the interrupted collection is recorded as such and did not touch the graphs
    let status: String = db.with(|c| Ok(c.query_row("SELECT status FROM osint_operations", [], |r| r.get(0))?)).unwrap();
    assert_eq!((status.as_str(), ops_before), ("failed", 1));
    // switching between graphs in sequence returns each one's own state
    for _ in 0..3 {
        for id in [g_copy, g, g_restored] {
            assert_eq!(state_of(&db, id), before[[g, g_copy, g_restored].iter().position(|x| *x == id).unwrap()]);
        }
    }
    drop(db);
    assert_eq!(integrity(&path), ("ok".into(), 0));
    cleanup(&path);
}

#[test]
fn a_failure_inside_the_save_transaction_changes_nothing() {
    let path = temp_db("midsave");
    let db = Db::open(&path).unwrap();
    let (_, g) = populate(&db);
    save(&db, g, custom_nodes(&db, g, 10.0), custom_workspace(1)).unwrap();
    let before = state_of(&db, g);
    // nodes and workspace are written before the version row: make that last step fail
    db.with(|c| Ok(c.execute_batch("CREATE TEMP TRIGGER fail_version BEFORE INSERT ON osint_graph_versions BEGIN SELECT RAISE(ABORT, 'simulated failure'); END;")?)).unwrap();
    let err = save(&db, g, custom_nodes(&db, g, 77.0), custom_workspace(2)).unwrap_err();
    assert!(err.to_string().contains("simulated failure"), "{err}");
    assert_eq!(state_of(&db, g), before, "a failed save must not leave partial graph records");
    db.with(|c| Ok(c.execute_batch("DROP TRIGGER fail_version;")?)).unwrap();
    // the next save works normally
    save(&db, g, custom_nodes(&db, g, 77.0), custom_workspace(2)).unwrap();
    assert_eq!(state_of(&db, g).0["marker"], 2);
    drop(db);
    assert_eq!(integrity(&path), ("ok".into(), 0));
    cleanup(&path);
}

#[test]
fn a_locked_database_or_a_full_disk_fails_the_save_cleanly() {
    let path = temp_db("locked");
    let db = Db::open(&path).unwrap();
    let (_, g) = populate(&db);
    save(&db, g, custom_nodes(&db, g, 10.0), custom_workspace(1)).unwrap();
    let before = state_of(&db, g);
    // another process holds the write lock longer than the busy timeout
    db.with(|c| Ok(c.execute_batch("PRAGMA busy_timeout = 200;")?)).unwrap();
    let other = Connection::open(&path).unwrap();
    other.execute_batch("BEGIN IMMEDIATE; UPDATE osint_graphs SET description = 'other writer' WHERE id = 0;").unwrap();
    let err = save(&db, g, custom_nodes(&db, g, 55.0), custom_workspace(9)).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("locked") || err.to_string().to_lowercase().contains("busy"), "{err}");
    other.execute_batch("ROLLBACK;").unwrap();
    assert_eq!(state_of(&db, g), before);
    // once the lock is released the same save succeeds
    save(&db, g, custom_nodes(&db, g, 55.0), custom_workspace(9)).unwrap();
    let saved = state_of(&db, g);
    // disk full: cap the database at its current size, then try a save that needs more pages
    db.with(|c| {
        let pages: i64 = c.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        c.execute_batch(&format!("PRAGMA max_page_count = {pages};"))?;
        Ok(())
    })
    .unwrap();
    let big = json!({ "layout": "force", "notes": "x".repeat(400_000), "marker": 10 });
    let err = save(&db, g, custom_nodes(&db, g, 66.0), big).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("full"), "{err}");
    assert_eq!(state_of(&db, g), saved, "a full disk must not leave partial graph records");
    drop(db);
    drop(other);
    assert_eq!(integrity(&path), ("ok".into(), 0));
    cleanup(&path);
}

/* ───────────── crash tests (child processes) ───────────── */

/// Child side: perform the requested crash scenario against the database file, then die.
fn child_main(spec: &str) -> ! {
    let (mode, path) = spec.split_once('|').expect("mode|path");
    let db = Db::open(Path::new(path)).unwrap();
    let g = db.with(|c| Ok(c.query_row("SELECT id FROM osint_graphs ORDER BY id LIMIT 1", [], |r| r.get::<_, i64>(0))?)).unwrap();
    match mode {
        // abort inside an open transaction, after the graph rows were already rewritten
        "abort-before-commit" => {
            let nodes = custom_nodes(&db, g, 999.0);
            let d = db.with(|c| store::graph_load(c, g, false)).unwrap();
            db.with::<()>(|c| {
                let t = c.unchecked_transaction()?;
                store::graph_save(&t, g, &GraphSave { base_revision: d.graph.revision, nodes, removed: vec![], workspace: custom_workspace(999), version_label: None, manual_version: false, base_state_revision: None, force: false })?;
                // proof for the parent that the rows were rewritten inside the open transaction
                std::fs::write(Path::new(path).with_extension("reached"), b"1").unwrap();
                std::process::abort();
            })
            .unwrap();
            unreachable!()
        }
        // save forever (each save consistent: every x and the workspace marker carry the same i)
        "save-loop" => {
            // continue from the last committed marker, so markers only grow across rounds unless a
            // committed save were lost
            let stored = db.with(|c| store::graph_load(c, g, false)).unwrap().workspace["marker"].as_i64().unwrap_or(0);
            let mut i = stored.max(1000);
            loop {
                i += 1;
                let nodes: Vec<GraphNodeState> = custom_nodes(&db, g, 0.0).into_iter().map(|n| GraphNodeState { x: Some(i as f64), ..n }).collect();
                let _ = save(&db, g, nodes, custom_workspace(i));
            }
        }
        other => panic!("unknown mode {other}"),
    }
}

fn spawn_child(test: &str, mode: &str, path: &Path) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, format!("{mode}|{}", path.display()))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

#[test]
fn a_process_dying_in_the_middle_of_a_save_keeps_the_last_valid_state() {
    if let Ok(spec) = std::env::var(CHILD_ENV) {
        child_main(&spec);
    }
    let path = temp_db("abort");
    {
        let db = Db::open(&path).unwrap();
        let (_, g) = populate(&db);
        save(&db, g, custom_nodes(&db, g, 10.0), custom_workspace(1)).unwrap();
    }
    let before = state_of(&Db::open(&path).unwrap(), 1);
    let status = spawn_child("osint::durability_tests::a_process_dying_in_the_middle_of_a_save_keeps_the_last_valid_state", "abort-before-commit", &path).wait().unwrap();
    assert!(!status.success(), "the child must have died");
    assert!(path.with_extension("reached").exists(), "the child died inside the save transaction, not before it");
    assert_eq!(integrity(&path), ("ok".into(), 0), "the database is intact after the crash");
    let db = Db::open(&path).unwrap();
    assert_eq!(state_of(&db, 1), before, "the uncommitted save left no trace; the last saved state is restored");
    // and the graph can be saved again
    save(&db, 1, custom_nodes(&db, 1, 20.0), custom_workspace(2)).unwrap();
    drop(db);
    cleanup(&path);
}

#[test]
fn killing_the_process_during_repeated_saves_never_leaves_a_mixed_state() {
    if let Ok(spec) = std::env::var(CHILD_ENV) {
        child_main(&spec);
    }
    let path = temp_db("kill");
    {
        let db = Db::open(&path).unwrap();
        populate(&db);
    }
    let mut last_marker = 0;
    for round in 0..5u64 {
        let mut child = spawn_child("osint::durability_tests::killing_the_process_during_repeated_saves_never_leaves_a_mixed_state", "save-loop", &path);
        std::thread::sleep(Duration::from_millis(600 + round * 170));
        child.kill().unwrap();
        let _ = child.wait();
        assert_eq!(integrity(&path), ("ok".into(), 0), "round {round}: integrity after the kill");
        let db = Db::open(&path).unwrap();
        let (ws, nodes, _, versions) = state_of(&db, 1);
        let marker = ws["marker"].as_i64().unwrap_or(0);
        if marker > 0 {
            assert!(nodes.iter().all(|n| n.x == Some(marker as f64)), "round {round}: positions and workspace come from the same save");
            // the newest version records exactly the saved state (written in the same transaction)
            let latest = db.with(|c| Ok(c.query_row("SELECT snapshot FROM osint_graph_versions WHERE graph_id = 1 ORDER BY number DESC LIMIT 1", [], |r| r.get::<_, String>(0))?)).unwrap();
            let snap: Value = serde_json::from_str(&latest).unwrap();
            assert_eq!(snap["workspace"]["marker"], marker, "round {round}: the latest version matches the graph");
        }
        assert!(!versions.is_empty());
        assert!(marker >= last_marker, "round {round}: committed saves are never lost");
        last_marker = marker;
    }
    assert!(last_marker > 1000, "the child committed saves before being killed (marker {last_marker})");
    cleanup(&path);
}

/* ───────────── concurrent editors ───────────── */

#[test]
fn stale_editors_are_refused_for_every_kind_of_change_and_collected_entities_survive() {
    let path = temp_db("conflicts");
    let db = Db::open(&path).unwrap();
    let (inv, g) = populate(&db);
    save(&db, g, custom_nodes(&db, g, 10.0), custom_workspace(1)).unwrap();
    type Edit = fn(&mut Vec<GraphNodeState>, &mut Value);
    let edits: [(&str, Edit); 6] = [
        ("positions", |n, _| n[0].x = Some(-5000.0)),
        ("groups", |n, w| {
            n[3].group = Some("g2".into());
            w["groups"] = json!([{ "id": "g2", "label": "Other", "color": "#3fb68b" }]);
        }),
        ("hidden nodes", |n, _| n[2].hidden = true),
        ("viewport", |_, w| w["viewport"] = json!({ "x": 1, "y": 2, "zoom": 0.5 })),
        ("layout", |_, w| w["layout"] = json!("radial")),
        ("filters", |_, w| w["filters"]["hiddenTypes"] = json!(["ip"])),
    ];
    for (name, edit) in edits {
        // both editors load the same saved state
        let a = db.with(|c| store::graph_load(c, g, false)).unwrap();
        let b = a.clone();
        // entities are collected into the graph while both edit
        let n_before = a.nodes.len();
        run(&db, inv, &Observation { evidence: ev("dns", &format!("new data during {name}")), entities: vec![ent(EntityType::Domain, &format!("{}.example.com", name.replace(' ', "-")))], relationships: vec![] });
        let save_with = |d: &store::GraphData, edit: Edit, force: bool| {
            let mut nodes = d.nodes.clone();
            let mut ws = d.workspace.clone();
            edit(&mut nodes, &mut ws);
            tx(&db, |c| store::graph_save(c, g, &GraphSave { base_revision: d.graph.revision, nodes, removed: vec![], workspace: ws, version_label: None, manual_version: false, base_state_revision: Some(d.graph.state_revision), force }))
        };
        // editor A saves its change first: accepted (collection in between is not a conflict)
        save_with(&a, edit, false).unwrap_or_else(|e| panic!("{name}: first save refused: {e}"));
        let after_a = state_of(&db, g);
        // editor B's stale save is refused and changes nothing
        let err = save_with(&b, |_, w| w["notes"] = json!("editor B"), false).unwrap_err();
        assert_eq!(err.kind(), "conflict", "{name}");
        assert_eq!(state_of(&db, g), after_a, "{name}: a refused save writes nothing");
        // B overwrites deliberately: B's presentation wins, A's state stays in the history,
        // and the entity collected meanwhile is still in the graph
        let versions_before = db.with(|c| store::versions(c, g)).unwrap().len();
        save_with(&b, |_, w| w["notes"] = json!("editor B"), true).unwrap();
        let d = db.with(|c| store::graph_load(c, g, false)).unwrap();
        assert_eq!(d.workspace["notes"], "editor B", "{name}");
        assert_eq!(d.nodes.len(), n_before + 1, "{name}: the collected entity is kept by both saves");
        assert!(db.with(|c| store::versions(c, g)).unwrap().len() > versions_before, "{name}: the overwritten state is kept as a version");
    }
    // a restore elsewhere also makes open editors stale
    let a = db.with(|c| store::graph_load(c, g, false)).unwrap();
    let oldest = db.with(|c| store::versions(c, g)).unwrap().last().unwrap().id;
    tx(&db, |c| store::version_restore(c, oldest)).unwrap();
    let err = tx(&db, |c| store::graph_save(c, g, &GraphSave { base_revision: a.graph.revision, nodes: a.nodes.clone(), removed: vec![], workspace: a.workspace.clone(), version_label: None, manual_version: false, base_state_revision: Some(a.graph.state_revision), force: false })).unwrap_err();
    assert_eq!(err.kind(), "conflict");
    drop(db);
    assert_eq!(integrity(&path), ("ok".into(), 0));
    cleanup(&path);
}
