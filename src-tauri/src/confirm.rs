// SPDX-License-Identifier: Apache-2.0
//! Native OS confirmation dialogs.
//!
//! The web view can call any registered command, so an in-page "Confirm" button alone
//! cannot protect high-consequence actions if the frontend were ever compromised. The
//! dialogs here are created by the Rust process through the OS (Win32 / GTK);
//! page script cannot see, script or click them. Actions that start processes
//! (tool runs, installations) must pass through `native()`.
//!
//! Mission 7: a page cannot click the dialog, but it decides when the dialog appears. It could
//! open one while the user is typing, and the next Enter or Space would approve it. So Cancel is
//! the default button, the approving button stays disabled for `APPROVE_DELAY_MS` after the dialog
//! appears, and only one confirmation is shown at a time. The dialogs are built here (a Windows
//! task dialog, a GTK dialog on Linux) because the dialog plugin makes the first button, the
//! approving one, the default.

use tauri::AppHandle;

/// How long the approving button stays disabled after the dialog appears.
pub const APPROVE_DELAY_MS: u64 = 1000;

/// Confirmations are shown one at a time: a page cannot stack several.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Show a modal dialog with a custom confirm label and Cancel. Returns true only when the user
/// explicitly chose the confirm button, after it became available.
pub async fn native(app: &AppHandle, title: &str, message: String, confirm_label: &str) -> bool {
    let _one = ONE_AT_A_TIME.lock().await;
    // values in the message (names, titles, arguments) cannot reorder, hide or add text
    imp::ask(app, title, crate::util::dialog_text(&message), confirm_label).await
}

#[cfg(windows)]
mod imp {
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicBool, Ordering};

    use tauri::{AppHandle, Manager};
    use windows_sys::Win32::Foundation::{HWND, LPARAM, WPARAM};
    use windows_sys::Win32::UI::Controls::{
        TaskDialogIndirect, TASKDIALOGCONFIG, TASKDIALOGCONFIG_0, TASKDIALOG_BUTTON, TDCBF_CANCEL_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION, TDF_CALLBACK_TIMER, TDF_POSITION_RELATIVE_TO_WINDOW, TDF_SIZE_TO_CONTENT, TDM_ENABLE_BUTTON, TDN_BUTTON_CLICKED, TDN_CREATED, TDN_TIMER,
        TD_WARNING_ICON,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{SendMessageW, IDCANCEL};

    const APPROVE: i32 = 100;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Disables the approving button when the dialog is created, and enables it once the delay
    /// has passed (the timer notification carries the milliseconds since creation).
    unsafe extern "system" fn callback(hwnd: HWND, msg: u32, wparam: WPARAM, _lparam: LPARAM, data: isize) -> i32 {
        // SAFETY: `data` is the address of the `AtomicBool` that `show` keeps alive until
        // `TaskDialogIndirect` returns, and notifications only arrive before that
        let enabled = unsafe { &*(data as *const AtomicBool) };
        let msg = msg as i32;
        if msg == TDN_CREATED {
            unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON as u32, APPROVE as WPARAM, 0) };
        } else if msg == TDN_TIMER && !enabled.load(Ordering::Relaxed) && wparam as u64 >= super::APPROVE_DELAY_MS {
            enabled.store(true, Ordering::Relaxed);
            unsafe { SendMessageW(hwnd, TDM_ENABLE_BUTTON as u32, APPROVE as WPARAM, 1) };
        } else if msg == TDN_BUTTON_CLICKED && wparam as i32 == APPROVE && !enabled.load(Ordering::Relaxed) {
            // a click on the approving button while it is disabled (only a synthetic one can
            // arrive) does not close the dialog: S_FALSE (Mission 7)
            return 1;
        }
        0
    }

    fn show(parent: HWND, title: &str, message: &str, label: &str) -> bool {
        let (title, message, label) = (wide(title), wide(message), wide(label));
        let buttons = [TASKDIALOG_BUTTON { nButtonID: APPROVE, pszButtonText: label.as_ptr() }];
        let enabled = AtomicBool::new(false);
        let config = TASKDIALOGCONFIG {
            cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
            hwndParent: parent,
            dwFlags: TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW | TDF_SIZE_TO_CONTENT | TDF_CALLBACK_TIMER,
            dwCommonButtons: TDCBF_CANCEL_BUTTON,
            pszWindowTitle: title.as_ptr(),
            Anonymous1: TASKDIALOGCONFIG_0 { pszMainIcon: TD_WARNING_ICON },
            pszContent: message.as_ptr(),
            cButtons: buttons.len() as u32,
            pButtons: buttons.as_ptr(),
            // Enter and Space press Cancel; Escape and the close box cancel too
            nDefaultButton: IDCANCEL,
            pfCallback: Some(callback),
            lpCallbackData: &enabled as *const AtomicBool as isize,
            ..Default::default()
        };
        let mut pressed = 0;
        // SAFETY: every pointer in `config` refers to a local that outlives the call
        let hr = unsafe { TaskDialogIndirect(&config, &mut pressed, null_mut(), null_mut()) };
        hr == 0 && pressed == APPROVE
    }

    pub async fn ask(app: &AppHandle, title: &str, message: String, label: &str) -> bool {
        let parent = app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map_or(0isize, |h| h.0 as isize);
        let (title, label) = (title.to_string(), label.to_string());
        // a task dialog runs its own message loop: never on the async runtime's threads
        tauri::async_runtime::spawn_blocking(move || show(parent as HWND, &title, &message, &label)).await.unwrap_or(false)
    }

    /// Mission 7: while the approving button is disabled, a click on it (only a synthetic one can
    /// arrive, such as TDM_CLICK_BUTTON) keeps the dialog open; Cancel always closes it.
    #[test]
    fn an_early_click_on_approve_keeps_the_dialog_open() {
        let enabled = AtomicBool::new(false);
        let data = &enabled as *const AtomicBool as isize;
        let click = |button: i32| unsafe { callback(null_mut(), TDN_BUTTON_CLICKED as u32, button as WPARAM, 0, data) };
        assert_eq!(click(APPROVE), 1, "S_FALSE: the dialog stays open");
        assert_eq!(click(2), 0, "Cancel closes it");
        enabled.store(true, Ordering::Relaxed);
        assert_eq!(click(APPROVE), 0, "after the delay, approving closes it");
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::Cell;

    use gtk::prelude::*;
    use tauri::{AppHandle, Manager};

    pub async fn ask(app: &AppHandle, title: &str, message: String, label: &str) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let handle = app.clone();
        let (title, label) = (title.to_string(), label.to_string());
        // GTK objects live on the main thread; the dialog answers through its `response` signal
        let shown = app.run_on_main_thread(move || {
            let parent = handle.get_webview_window("main").and_then(|w| w.gtk_window().ok());
            let dialog = gtk::MessageDialog::new(parent.as_ref(), gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT, gtk::MessageType::Warning, gtk::ButtonsType::None, &message);
            dialog.set_title(&title);
            dialog.add_button("Cancel", gtk::ResponseType::Cancel);
            let approve = dialog.add_button(&label, gtk::ResponseType::Accept);
            // Enter activates Cancel; the approving button waits a moment
            dialog.set_default_response(gtk::ResponseType::Cancel);
            approve.set_sensitive(false);
            let later = approve.downgrade();
            gtk::glib::timeout_add_local_once(std::time::Duration::from_millis(super::APPROVE_DELAY_MS), move || {
                if let Some(b) = later.upgrade() {
                    b.set_sensitive(true);
                }
            });
            let tx = Cell::new(Some(tx));
            dialog.connect_response(move |d, answer| {
                // closing emits a second response: only the first one counts
                let Some(tx) = tx.take() else { return };
                let _ = tx.send(answer == gtk::ResponseType::Accept);
                if answer != gtk::ResponseType::DeleteEvent {
                    d.close();
                }
            });
            dialog.show_all();
            if let Some(cancel) = dialog.widget_for_response(gtk::ResponseType::Cancel) {
                cancel.grab_focus();
            }
        });
        if shown.is_err() {
            return false;
        }
        rx.await.unwrap_or(false)
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use tauri::{AppHandle, Manager};
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

    pub async fn ask(app: &AppHandle, title: &str, message: String, label: &str) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut dialog = app.dialog().message(message).title(title).kind(MessageDialogKind::Warning).buttons(MessageDialogButtons::OkCancelCustom(label.to_string(), "Cancel".to_string()));
        if let Some(window) = app.get_webview_window("main") {
            dialog = dialog.parent(&window);
        }
        dialog.show(move |ok| {
            let _ = tx.send(ok);
        });
        rx.await.unwrap_or(false)
    }
}
