//! When Cyber Hub cannot start (its database was written by a newer version, is damaged or is
//! locked), it says why in a native message box before it exits (Mission 7). A release build has no
//! console, so without this the window would simply never appear.

/// The message box's title.
pub const TITLE: &str = "Cyber Hub could not start";

/// Shows why Cyber Hub cannot start, then exits with status 1.
pub fn fail(reason: &str) -> ! {
    let text = message(reason);
    eprintln!("{TITLE}: {text}");
    imp::show(TITLE, &text);
    std::process::exit(1)
}

/// The text of the message box: the reason, without the framework's prefix, and nothing that
/// could disguise it.
pub fn message(reason: &str) -> String {
    let reason = reason.strip_prefix("error encountered during setup hook: ").unwrap_or(reason);
    crate::util::dialog_text(reason.trim())
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn show(title: &str, text: &str) {
        let (title, text) = (wide(title), wide(text));
        // SAFETY: both strings are NUL-terminated and outlive the call; no owner window
        unsafe { MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR | MB_SETFOREGROUND) };
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use gtk::prelude::*;

    pub fn show(title: &str, text: &str) {
        // without a display there is nobody to tell: the message is on standard error
        if gtk::init().is_err() {
            return;
        }
        let dialog = gtk::MessageDialog::new(None::<&gtk::Window>, gtk::DialogFlags::MODAL, gtk::MessageType::Error, gtk::ButtonsType::Close, text);
        dialog.set_title(title);
        dialog.run();
        dialog.close();
        while gtk::events_pending() {
            gtk::main_iteration();
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    pub fn show(_title: &str, _text: &str) {}
}

#[cfg(test)]
mod tests {
    /// Mission 7: the message is the reason itself, readable, with nothing that could disguise it.
    #[test]
    fn the_message_is_the_reason_without_the_framework_prefix() {
        let m = super::message("error encountered during setup hook: This database was written by a newer version of Cyber Hub (schema 40; this version supports up to 32).");
        assert!(m.starts_with("This database was written by a newer version"), "{m}");
        assert_eq!(super::message("x\u{202E}y"), "x<U+202E>y");
    }
}
