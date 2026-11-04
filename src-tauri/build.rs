fn main() {
    // `bundle.externalBin` (tauri.conf.json) makes the bundler install the staged
    // `binaries/cyberhub-mcp-<triple>` next to the app (see scripts/build-sidecar.mjs).
    // tauri-build would also copy that staged file to `target/<profile>/cyberhub-mcp`, which is
    // where cargo itself writes the `cyberhub-mcp` binary of this crate; a stale or missing staged
    // copy would then replace or break the freshly built one in dev builds and tests. The bundler
    // reads the staged file directly, so the build-script copy is not needed: drop externalBin
    // from the configuration tauri-build sees, keeping any overrides the Tauri CLI passed.
    let mut overrides: serde_json::Value = std::env::var("TAURI_CONFIG")
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    let bundle = overrides.as_object_mut().unwrap().entry("bundle").or_insert_with(|| serde_json::json!({}));
    if !bundle.is_object() {
        *bundle = serde_json::json!({});
    }
    bundle.as_object_mut().unwrap().insert("externalBin".into(), serde_json::Value::Null);
    // build scripts are single-threaded at this point; edition 2021 keeps set_var safe
    std::env::set_var("TAURI_CONFIG", overrides.to_string());
    tauri_build::build()
}
