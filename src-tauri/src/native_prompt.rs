//! A credential typed into a native operating-system dialog (Mission 6), so that it never passes
//! through the web view: on Windows the system's credential dialog (CredUI), on Linux a GTK dialog
//! in the app's own UI process. The web view can only ask for the dialog; the value goes from the
//! dialog to the OS credential store inside the backend and is never returned.

use tauri::AppHandle;

/// What the user typed: a user name and the secret.
pub struct Typed {
    pub user: String,
    pub secret: zeroize::Zeroizing<String>,
}

/// Asks for a secret. With `user_label`, the dialog also asks for a user name, prefilled with
/// `user`; without it, only the secret counts (Windows' dialog always shows a user name field: it is
/// prefilled with `user` and ignored). None when the user cancels. Blocks until the dialog closes,
/// so it is called from a blocking task, never from the UI thread.
pub fn ask(app: &AppHandle, title: &str, message: &str, user_label: Option<&str>, user: &str) -> Result<Option<Typed>, String> {
    imp::ask(app, title, message, user_label, user)
}

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use tauri::{AppHandle, Manager};
    use windows_sys::Win32::Foundation::ERROR_CANCELLED;
    use windows_sys::Win32::Security::Credentials::{CredPackAuthenticationBufferW, CredUIPromptForWindowsCredentialsW, CredUnPackAuthenticationBufferW, CREDUIWIN_GENERIC, CREDUI_INFOW};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use zeroize::Zeroize;

    use super::Typed;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn text(buf: &[u16]) -> String {
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    pub fn ask(app: &AppHandle, title: &str, message: &str, user_label: Option<&str>, user: &str) -> Result<Option<Typed>, String> {
        let hwnd = app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map_or(null_mut(), |h| h.0);
        let caption = wide(title);
        let body = wide(&match user_label {
            Some(label) => format!("{message}\n\n{label}: the first field. The secret: the password field."),
            None => format!("{message}\n\nType it in the password field; the first field is not used."),
        });
        let info = CREDUI_INFOW { cbSize: std::mem::size_of::<CREDUI_INFOW>() as u32, hwndParent: hwnd, pszMessageText: body.as_ptr(), pszCaptionText: caption.as_ptr(), hbmBanner: null_mut() };
        // the dialog prefilled with the known user name
        let mut packed: Vec<u8> = Vec::new();
        if !user.is_empty() {
            let (u, p) = (wide(user), wide(""));
            let mut size: u32 = 0;
            // the first call reports the size
            unsafe { CredPackAuthenticationBufferW(0, u.as_ptr(), p.as_ptr(), null_mut(), &mut size) };
            packed = vec![0u8; size as usize];
            if size == 0 || unsafe { CredPackAuthenticationBufferW(0, u.as_ptr(), p.as_ptr(), packed.as_mut_ptr(), &mut size) } == 0 {
                packed.clear();
            }
        }
        let mut package: u32 = 0;
        let mut out: *mut c_void = null_mut();
        let mut out_size: u32 = 0;
        let mut save = 0;
        let (inbuf, inlen) = if packed.is_empty() { (null(), 0) } else { (packed.as_ptr() as *const c_void, packed.len() as u32) };
        let rc = unsafe { CredUIPromptForWindowsCredentialsW(&info, 0, &mut package, inbuf, inlen, &mut out, &mut out_size, &mut save, CREDUIWIN_GENERIC) };
        if rc == ERROR_CANCELLED {
            return Ok(None);
        }
        if rc != 0 || out.is_null() {
            return Err(format!("The credential dialog could not be shown (error {rc})"));
        }
        let mut name = vec![0u16; 514];
        let mut name_len = name.len() as u32;
        let mut domain = vec![0u16; 340];
        let mut domain_len = domain.len() as u32;
        let mut secret = vec![0u16; 4097];
        let mut secret_len = secret.len() as u32;
        let ok = unsafe { CredUnPackAuthenticationBufferW(0, out, out_size, name.as_mut_ptr(), &mut name_len, domain.as_mut_ptr(), &mut domain_len, secret.as_mut_ptr(), &mut secret_len) };
        // the packed answer is wiped before it is freed
        unsafe {
            std::slice::from_raw_parts_mut(out as *mut u8, out_size as usize).zeroize();
            CoTaskMemFree(out);
        }
        let result = if ok == 0 {
            Err("The credential could not be read from the dialog (a secret longer than 4 KB is refused)".to_string())
        } else {
            // a name typed as DOMAIN\user comes back split; it is put back together as typed
            let (name, domain) = (text(&name), text(&domain));
            let user = if domain.is_empty() { name } else { format!("{domain}\\{name}") };
            Ok(Some(Typed { user, secret: zeroize::Zeroizing::new(text(&secret)) }))
        };
        secret.zeroize();
        result
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::cell::Cell;

    use gtk::prelude::*;
    use tauri::{AppHandle, Manager};

    use super::Typed;

    pub fn ask(app: &AppHandle, title: &str, message: &str, user_label: Option<&str>, user: &str) -> Result<Option<Typed>, String> {
        let (tx, rx) = std::sync::mpsc::channel::<Option<(String, String)>>();
        let handle = app.clone();
        let (title, message, user_label, user) = (title.to_string(), message.to_string(), user_label.map(String::from), user.to_string());
        // GTK objects live on the main thread: the dialog is built there and answers through its
        // `response` signal (no nested main loop, so the app's event loop is never re-entered)
        app.run_on_main_thread(move || {
            let parent = handle.get_webview_window("main").and_then(|w| w.gtk_window().ok());
            let dialog = gtk::Dialog::with_buttons(Some(&title), parent.as_ref(), gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT, &[("Cancel", gtk::ResponseType::Cancel), ("Store", gtk::ResponseType::Accept)]);
            let area = dialog.content_area();
            area.set_spacing(8);
            area.set_border_width(12);
            let text = gtk::Label::new(Some(&message));
            text.set_line_wrap(true);
            text.set_max_width_chars(60);
            text.set_xalign(0.0);
            area.add(&text);
            let user_entry = gtk::Entry::new();
            if let Some(label) = &user_label {
                let l = gtk::Label::new(Some(label));
                l.set_xalign(0.0);
                area.add(&l);
                user_entry.set_text(&user);
                area.add(&user_entry);
            }
            let l = gtk::Label::new(Some("Secret"));
            l.set_xalign(0.0);
            area.add(&l);
            let secret_entry = gtk::Entry::new();
            secret_entry.set_visibility(false);
            secret_entry.set_input_purpose(gtk::InputPurpose::Password);
            secret_entry.set_activates_default(true);
            area.add(&secret_entry);
            dialog.set_default_response(gtk::ResponseType::Accept);
            let tx = Cell::new(Some(tx));
            let secret_field = secret_entry.clone();
            dialog.connect_response(move |d, answer| {
                // closing emits a second response: only the first one counts
                let Some(tx) = tx.take() else { return };
                let out = (answer == gtk::ResponseType::Accept).then(|| (user_entry.text().to_string(), secret_field.text().to_string()));
                secret_field.set_text("");
                let _ = tx.send(out);
                // a window-manager close (DeleteEvent) destroys the dialog by itself
                if answer != gtk::ResponseType::DeleteEvent {
                    d.close();
                }
            });
            dialog.show_all();
            secret_entry.grab_focus();
        })
        .map_err(|e| format!("The credential dialog could not be shown: {e}"))?;
        let answer = rx.recv().map_err(|_| "The credential dialog closed without an answer".to_string())?;
        Ok(answer.map(|(user, secret)| Typed { user, secret: zeroize::Zeroizing::new(secret) }))
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use tauri::AppHandle;

    use super::Typed;

    pub fn ask(_app: &AppHandle, _title: &str, _message: &str, _user_label: Option<&str>, _user: &str) -> Result<Option<Typed>, String> {
        Err("Credentials can be typed into Cyber Hub on Windows and Linux only; use cyberhub-keys taxii-set on this computer".into())
    }
}
