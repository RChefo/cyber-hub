//! Cyber Hub — Tauri backend.
//!
//! Layers: frontend → Tauri commands (`commands/*`) → domain modules
//! (`process`, `targets`, `scope`, `detect`, `redact`, `confirm`, `catalog`) → local SQLite (`db`).

mod catalog;
mod commands;
mod confirm;
mod db;
mod detect;
mod error;
mod process;
/// Developer-only credential provisioning (`cyberhub-keys`); not compiled into the app.
#[cfg(feature = "provisioning")]
pub mod provision;
mod redact;
mod scope;
mod targets;
mod ti;
mod util;
mod vt;
mod vtfile;

use tauri::Manager;

use commands::{activity, intel, library, projects, system, threat_intel, tools, virustotal, wordlists};

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let database = db::Db::open(&dir.join("cyberhub.db"))?;
            tools::sync_catalog(&database)?;
            app.manage(database);
            app.manage(process::ProcessManager::default());
            app.manage(virustotal::VtState::new()?);
            app.manage(threat_intel::TiState::new()?);
            // remove target-file snapshots left behind by a crash
            tools::clean_runtime_dir(app.handle());
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
            intel::cve_get_cached,
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
            threat_intel::ti_saved_add,
            threat_intel::ti_saved_remove,
            threat_intel::ti_export,
            // system
            system::system_info,
            system::open_terminal,
        ])
        .build(tauri::generate_context!())
        .expect("error while building Cyber Hub")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                // never leave tool processes running after Cyber Hub exits
                let had_runs = !app.state::<process::ProcessManager>().running_ids().is_empty();
                app.state::<process::ProcessManager>().kill_all_now();
                if had_runs {
                    // give terminated processes a moment to release snapshot files
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                tools::clean_runtime_dir(app);
            }
        });
}
