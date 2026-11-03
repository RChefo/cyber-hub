//! Native OS confirmation dialogs.
//!
//! The web view can call any registered command, so an in-page "Confirm" button alone
//! cannot protect high-consequence actions if the frontend were ever compromised. The
//! dialogs here are created by the Rust process through the OS (Win32 / AppKit / GTK);
//! page script cannot see, script or click them. Actions that start processes
//! (tool runs, installations) must pass through `native()`.

use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

/// Show a modal OK/Cancel dialog with a custom confirm label. Returns true only when the
/// user explicitly chose the confirm button.
pub async fn native(app: &AppHandle, title: &str, message: String, confirm_label: &str) -> bool {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let mut dialog = app
        .dialog()
        .message(message)
        .title(title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(confirm_label.to_string(), "Cancel".to_string()));
    if let Some(window) = app.get_webview_window("main") {
        dialog = dialog.parent(&window);
    }
    dialog.show(move |ok| {
        let _ = tx.send(ok);
    });
    rx.await.unwrap_or(false)
}
