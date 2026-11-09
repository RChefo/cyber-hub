//! Cyber Hub — Tauri backend.
//!
//! Layers: frontend → Tauri commands (`commands/*`) → domain modules
//! (`process`, `targets`, `scope`, `detect`, `redact`, `confirm`, `catalog`) → local SQLite (`db`).

mod catalog;
mod commands;
mod confirm;
mod cvss;
mod db;
mod methodology;
mod detect;
pub mod osint;
mod error;
pub mod mcp;
mod process;
/// Developer-only credential provisioning (`cyberhub-keys`); not compiled into the app.
#[cfg(feature = "provisioning")]
pub mod provision;
mod redact;
mod redirects;
mod restore;
mod scope;
mod sectools;
mod targets;
mod ti;
mod updates;
mod util;
mod vt;
mod vtfile;
mod workspace;
mod yaml;

use tauri::{AppHandle, Manager};

use commands::{activity, analysis as analysis_commands, apisec as apisec_commands, sbom as sbom_commands, assistant as assistant_commands, intel, library, mcp as mcp_commands, osint as osint_commands, projects, sectools as sectool_commands, system, discovery as discovery_commands, threat_intel, tools, updates as update_commands, virustotal, vulns as vuln_commands, wordlists, workflows as workflow_commands, workspace as workspace_commands};

/// Leaves no work behind when Cyber Hub exits: normal exit, restart after an update, and right
/// before an update installer takes over on Windows. Safe to call more than once.
pub(crate) fn shutdown(app: &AppHandle) {
    // never leave tool processes running after Cyber Hub exits
    let had_runs = !app.state::<process::ProcessManager>().running_ids().is_empty();
    app.state::<process::ProcessManager>().kill_all_now();
    if had_runs {
        // give terminated processes a moment to release snapshot files
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    tools::clean_runtime_dir(app);
    // close the MCP bridge and remove its connection files
    app.state::<std::sync::Arc<mcp::bridge::Bridge>>().stop();
    // fold the write-ahead log into the database file (committed data is durable either way)
    let _ = app.state::<db::Db>().with(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?));
}

pub fn run() {
    tauri::Builder::default()
        // must be registered first: a second launch exits here, before setup clears runtime and
        // MCP files the first instance is using; its arguments are ignored, the window is focused
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.unminimize();
                let _ = w.show();
                let _ = w.set_focus();
            }
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        // signed updates; driven only by the backend (`updates`), no permission for the web view
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let dir = util::data_dir(app)?;
            std::fs::create_dir_all(&dir)?;
            // The data folder holds the database (projects, findings, investigations and evidence):
            // only the user may enter it, whatever the umask made of it (on Windows the profile
            // folder is already private to the user)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            // Tools inherit Cyber Hub's working directory, and relative file names in arguments are
            // validated against it. Use a private folder, so a relative name never resolves to (or
            // writes into) the installation folder or wherever the app happened to be started.
            let work = dir.join("work");
            std::fs::create_dir_all(&work)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))?;
            }
            std::env::set_current_dir(&work)?;
            // a restore staged before the restart replaces the database before it is opened; a
            // restored database that does not open is set aside and the previous one goes back
            let db_path = dir.join(restore::DB_NAME);
            let mut restoring = restore::swap_pending(&dir);
            let database = match db::Db::open(&db_path) {
                Ok(d) => d,
                Err(e) => match restoring.as_mut().filter(|s| !s.done()) {
                    Some(swap) => {
                        restore::undo(&dir, swap, &e)?;
                        db::Db::open(&db_path)?
                    }
                    None => return Err(e.into()),
                },
            };
            let restored = restoring.as_mut().map(|s| {
                if s.done() {
                    return s.outcome().clone();
                }
                // a restored database does not turn the MCP bridge on by itself
                s.outcome_mut().mcp_turned_off = database
                    .with(|c| Ok(c.execute("UPDATE user_preferences SET value = 'false' WHERE key = ?1 AND value = 'true'", [mcp::ops::ENABLED_PREF])?))
                    .is_ok_and(|n| n > 0);
                restore::finish(&dir, s)
            });
            if let Some(o) = &restored {
                let (title, detail) = match (&o.error, o.ok) {
                    (None, _) => ("Database restored", format!("{}; the previous database is kept in {}", o.source, o.kept_in.as_deref().unwrap_or("backups"))),
                    (Some(e), true) => ("Database restored with a warning", e.clone()),
                    (Some(e), false) => (if o.retry { "Database restore postponed" } else { "Database restore failed" }, e.clone()),
                };
                let _ = database.with(|c| activity::log(c, "restore", title, &detail, None, None, None));
            }
            // no evidence sweep at a start that restored or tried to restore a backup
            let skip_sweep = restored.is_some() || restore::sorting_evidence(&dir);
            app.manage(workspace_commands::RestoreState::new(restored));
            tools::sync_catalog(&database)?;
            app.manage(database);
            app.manage(process::ProcessManager::default());
            app.manage(virustotal::VtState::new()?);
            app.manage(threat_intel::TiState::new()?);
            app.manage(std::sync::Arc::new(mcp::bridge::Bridge::default()));
            app.manage(mcp::ops::LiveRuns::default());
            app.manage(std::sync::Arc::new(osint::discovery::OsintState::default()));
            app.manage(osint_commands::ImportState::default());
            app.manage(workspace_commands::ScanImports::default());
            app.manage(std::sync::Arc::new(updates::Updates::load(&app.state::<db::Db>())));
            // evidence files (content-addressed, private folder); leftovers of an interrupted copy
            // and files no record refers to any more are removed
            let evidence = std::sync::Arc::new(workspace::evidence::EvidenceStore::new(dir.join("evidence")));
            // not while a restore is in progress, nor right after one: some files belong to the
            // previous database
            if skip_sweep {
                eprintln!("Cyber Hub: evidence folder not swept at this start (database restore)");
            } else if let Err(e) = evidence.sweep(&app.state::<db::Db>()) {
                eprintln!("Cyber Hub: evidence folder not checked: {e}");
            }
            app.manage(evidence);
            app.manage(discovery_commands::DiscoveryState::default());
            app.manage(workflow_commands::WorkflowState::default());
            app.manage(assistant_commands::AssistantState::default());
            // collections interrupted by a crash or exit are marked as such
            osint::discovery::recover_interrupted(&app.state::<db::Db>());
            // remove target-file snapshots left behind by a crash
            tools::clean_runtime_dir(app.handle());
            // MCP bridge: off unless the user turned it on on the MCP page
            let enabled = mcp_commands::enabled_pref(&app.state::<db::Db>());
            let _ = std::fs::remove_dir_all(dir.join("mcp")); // stale connection files from a crash
            if enabled {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = mcp_commands::start_bridge(&handle).await {
                        eprintln!("Cyber Hub: MCP bridge not started: {e}");
                    }
                });
            }
            // automatic update checks (off the startup path; nothing is installed without approval)
            updates::start_scheduler(app.handle().clone());
            // scheduled workflows (passive steps only) while Cyber Hub runs
            workflow_commands::start_scheduler(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // activity, preferences, favorites, tasks
            activity::activity_list,
            activity::activity_log,
            activity::activity_clear,
            activity::activity_daily,
            activity::prefs_get_all,
            activity::prefs_set,
            activity::favorites_list,
            activity::favorite_toggle,
            activity::tasks_list,
            activity::task_upsert,
            activity::task_delete,
            // libraries
            library::custom_resources_list,
            library::custom_resource_upsert,
            library::custom_resource_delete,
            library::resource_visit,
            library::resource_recent,
            library::saved_commands_list,
            library::saved_command_upsert,
            library::saved_command_delete,
            library::command_history_list,
            library::command_history_add,
            library::command_history_clear,
            library::saved_dorks_list,
            library::saved_dork_upsert,
            library::saved_dork_delete,
            library::dork_history_list,
            library::dork_history_add,
            library::dork_history_clear,
            library::custom_payloads_list,
            library::custom_payload_upsert,
            library::custom_payload_delete,
            // projects
            projects::projects_list,
            projects::project_get,
            projects::project_upsert,
            projects::project_delete,
            projects::scope_classify,
            projects::project_target_add,
            projects::project_target_delete,
            projects::scope_check,
            projects::findings_list,
            projects::finding_upsert,
            projects::finding_delete,
            projects::project_tool_history,
            projects::project_report,
            projects::project_report_export,
            // shared project data: assets, finding lifecycle, evidence, scope history, timeline
            workspace_commands::assets_list,
            workspace_commands::asset_add,
            workspace_commands::asset_set_status,
            workspace_commands::asset_observations,
            workspace_commands::asset_delete,
            workspace_commands::finding_set_status,
            workspace_commands::finding_add_note,
            workspace_commands::finding_history,
            workspace_commands::finding_links,
            workspace_commands::finding_link,
            workspace_commands::finding_unlink,
            workspace_commands::scope_history,
            workspace_commands::scope_decide,
            workspace_commands::project_timeline,
            workspace_commands::evidence_list,
            workspace_commands::evidence_add_text,
            workspace_commands::evidence_add_file,
            workspace_commands::evidence_link_execution,
            workspace_commands::evidence_link_osint,
            workspace_commands::evidence_export,
            workspace_commands::evidence_verify,
            workspace_commands::evidence_delete,
            workspace_commands::scan_import_pick,
            workspace_commands::scan_import_preview,
            workspace_commands::scan_import_remap,
            workspace_commands::scan_import_commit,
            workspace_commands::scan_import_discard,
            workspace_commands::scan_imports_list,
            workspace_commands::finding_templates_list,
            workspace_commands::finding_template_save,
            workspace_commands::finding_template_delete,
            workspace_commands::finding_template_used,
            workspace_commands::finding_templates_add_starters,
            workspace_commands::finding_templates_export,
            workspace_commands::finding_templates_import,
            workspace_commands::cvss_score,
            workspace_commands::findings_export,
            workspace_commands::wstg_catalog,
            workspace_commands::checklist_items,
            workspace_commands::checklist_set,
            workspace_commands::database_backup,
            apisec_commands::api_spec_import,
            apisec_commands::api_specs_list,
            apisec_commands::api_spec_get,
            apisec_commands::api_spec_delete,
            apisec_commands::api_issue_record,
            apisec_commands::api_spec_compare,
            apisec_commands::api_compare_record,
            sbom_commands::sbom_import,
            sbom_commands::sboms_list,
            sbom_commands::sbom_get,
            sbom_commands::sbom_check,
            sbom_commands::sbom_record,
            sbom_commands::sbom_delete,
            sbom_commands::sbom_compare,
            sbom_commands::sbom_compare_record,
            workspace_commands::database_restore_inspect,
            workspace_commands::database_restore_apply,
            workspace_commands::database_restore_outcome,
            workspace_commands::database_restore_pending,
            workspace_commands::database_restore_cancel,
            workspace_commands::report_html,
            workspace_commands::report_export_html,
            workspace_commands::report_save_evidence,
            workspace_commands::report_printed,
            // attack surface discovery
            discovery_commands::discovery_passive_start,
            discovery_commands::discovery_http_start,
            discovery_commands::discovery_scan_start,
            discovery_commands::discovery_cancel,
            discovery_commands::discovery_running,
            discovery_commands::discovery_snapshots,
            discovery_commands::discovery_changes,
            // vulnerability management and bulk finding changes
            vuln_commands::vulns_list,
            vuln_commands::vuln_add,
            vuln_commands::vulns_refresh,
            vuln_commands::vuln_set_context,
            vuln_commands::vuln_set_status,
            vuln_commands::vuln_set_remediation,
            vuln_commands::vuln_verify,
            vuln_commands::vuln_history,
            vuln_commands::vuln_delete,
            vuln_commands::vuln_create_finding,
            vuln_commands::findings_bulk_status,
            vuln_commands::findings_bulk_edit,
            // workflow automation
            workflow_commands::workflow_nodes,
            workflow_commands::workflow_templates,
            workflow_commands::workflows_list,
            workflow_commands::workflow_save,
            workflow_commands::workflow_delete,
            workflow_commands::workflow_run,
            workflow_commands::workflow_cancel,
            workflow_commands::workflow_runs,
            workflow_commands::workflow_run_detail,
            // analysis and the project assistant
            analysis_commands::ioc_correlation,
            analysis_commands::exposure_paths,
            analysis_commands::discovery_compare,
            analysis_commands::runs_compare,
            assistant_commands::assistant_status,
            assistant_commands::assistant_context_preview,
            assistant_commands::assistant_ask,
            assistant_commands::assistant_forget,
            // security utilities
            sectool_commands::tls_analyze,
            sectool_commands::dns_intel,
            sectool_commands::http_send,
            sectool_commands::leak_scan_text,
            sectool_commands::leak_scan_pick,
            sectool_commands::container_scan_text,
            sectool_commands::container_scan_pick,
            sectool_commands::iac_scan_text,
            sectool_commands::iac_scan_pick,
            sectool_commands::linux_persist_scan_text,
            sectool_commands::linux_persist_scan_pick,
            sectool_commands::binary_analyze_pick,
            sectool_commands::pcap_analyze_pick,
            sectool_commands::log_analyze_text,
            sectool_commands::log_analyze_pick,
            sectool_commands::services_by_port,
            // tools & execution engine
            tools::tools_catalog,
            tools::tools_detection_list,
            tools::tools_scan,
            tools::package_managers,
            tools::tool_install,
            tools::tool_launch,
            tools::exec_validate,
            tools::exec_start,
            tools::exec_cancel,
            tools::exec_list,
            tools::exec_output,
            tools::exec_history_clear,
            // wordlists
            wordlists::wordlists_list,
            wordlists::wordlists_pick,
            wordlists::wordlists_choose_directory,
            wordlists::wordlists_clear_directory,
            wordlists::wordlists_scan,
            wordlists::wordlist_update,
            wordlists::wordlist_remove,
            wordlists::wordlist_preview,
            wordlists::wordlist_export,
            wordlists::wordlists_dir,
            // intelligence & network utilities
            intel::dns_lookup,
            intel::http_inspect,
            intel::cve_search,
            intel::cve_history,
            intel::cve_cache_stats,
            intel::cve_history_clear,
            // VirusTotal (requests are made only here, with the key from the OS credential store)
            virustotal::vt_lookup,
            virustotal::vt_recent,
            virustotal::vt_cache_clear,
            virustotal::vt_key_status,
            virustotal::vt_file_pick,
            virustotal::vt_file_forget,
            virustotal::vt_file_upload,
            virustotal::vt_file_cancel,
            virustotal::vt_analysis,
            // threat intelligence providers
            threat_intel::ti_providers,
            threat_intel::ti_provider_set_enabled,
            threat_intel::ti_detect,
            threat_intel::ti_lookup,
            threat_intel::ti_history,
            threat_intel::ti_history_clear,
            threat_intel::ti_cache_clear,
            threat_intel::ti_saved_list,
            threat_intel::ti_saved_export_stix,
            threat_intel::ti_saved_add,
            threat_intel::ti_saved_remove,
            threat_intel::ti_export,
            // MCP integration (MCP page; not reachable from MCP clients)
            mcp_commands::mcp_status,
            mcp_commands::mcp_set_enabled,
            mcp_commands::mcp_set_policy,
            mcp_commands::mcp_pending,
            mcp_commands::mcp_decide,
            mcp_commands::mcp_audit,
            mcp_commands::mcp_audit_clear,
            mcp_commands::mcp_catalog,
            mcp_commands::mcp_clients,
            mcp_commands::mcp_client_configs,
            // OSINT workspace
            osint_commands::osint_registry,
            osint_commands::osint_investigations,
            osint_commands::osint_investigation_get,
            osint_commands::osint_investigation_create,
            osint_commands::osint_investigation_update,
            osint_commands::osint_investigation_set_status,
            osint_commands::osint_investigation_delete,
            osint_commands::osint_compare,
            osint_commands::osint_entities,
            osint_commands::osint_entity,
            osint_commands::osint_relationship,
            osint_commands::osint_set_verification,
            osint_commands::osint_entity_update,
            osint_commands::osint_entity_delete,
            osint_commands::osint_relationship_delete,
            osint_commands::osint_entity_merge,
            osint_commands::osint_entity_add,
            osint_commands::osint_link,
            osint_commands::osint_neighbors,
            osint_commands::osint_entities_by_ids,
            osint_commands::osint_duplicates,
            osint_commands::osint_finding_from_entity,
            osint_commands::osint_graphs,
            osint_commands::osint_graph_create,
            osint_commands::osint_graph_load,
            osint_commands::osint_graph_save,
            osint_commands::osint_graph_save_as,
            osint_commands::osint_graph_duplicate,
            osint_commands::osint_graph_rename,
            osint_commands::osint_graph_delete,
            osint_commands::osint_versions,
            osint_commands::osint_version_create,
            osint_commands::osint_version_compare,
            osint_commands::osint_version_restore,
            osint_commands::osint_timeline,
            osint_commands::osint_analysis,
            osint_commands::osint_path,
            osint_commands::osint_suggestions,
            osint_commands::osint_discover,
            osint_commands::osint_operations,
            osint_commands::osint_operation,
            osint_commands::osint_operation_cancel,
            osint_commands::osint_operation_import,
            osint_commands::osint_import_sources,
            osint_commands::osint_import_internal,
            osint_commands::osint_export,
            osint_commands::osint_export_image,
            osint_commands::osint_report,
            osint_commands::osint_report_export,
            osint_commands::osint_import_pick,
            osint_commands::osint_import_preview,
            osint_commands::osint_import_apply,
            osint_commands::osint_import_discard,
            // updates (Settings → Updates)
            update_commands::update_status,
            update_commands::update_check,
            update_commands::update_download,
            update_commands::update_cancel,
            update_commands::update_install,
            update_commands::update_restart,
            update_commands::update_settings_set,
            // system
            system::system_info,
            system::open_terminal,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Cyber Hub")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                shutdown(app);
            }
        });
}
