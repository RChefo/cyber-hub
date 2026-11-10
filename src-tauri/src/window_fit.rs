//! The main window's first size on the screen it opens on (Mission 7).
//!
//! Sizes are logical pixels. At 150 % or 200 % scaling a 1920 × 1080 screen offers about
//! 1280 × 688 or 960 × 516 logical pixels once the taskbar or panel is taken away, so neither the
//! configured 1440 × 900 window nor the former 1100 × 700 minimum fitted. The window is created
//! hidden (`tauri.conf.json`), sized here to the monitor's work area, then shown.

/// The smallest window the layout is laid out for: it fits 1920 × 1080 at 200 % under the
/// Windows taskbar and the GNOME and KDE panels. `tauri.conf.json` declares the same minimum
/// (checked by a test).
pub const MIN: (f64, f64) = (800.0, 480.0);

/// The share of the work area a resized window takes, so its edges stay visible.
const SHARE: f64 = 0.94;

/// Below this work area the window opens maximized: a smaller window would waste the screen.
const MAXIMIZE_BELOW: (f64, f64) = (1024.0, 640.0);

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Fit {
    /// the window's size
    pub size: (f64, f64),
    /// its minimum size: `MIN`, or less on a screen smaller than that
    pub min: (f64, f64),
    pub maximize: bool,
}

/// The window's size for a work area of `work` logical pixels, given its configured size.
pub fn fit(configured: (f64, f64), work: (f64, f64)) -> Fit {
    // a screen smaller than the minimum still gets the whole window on it
    let min = (MIN.0.min(work.0), MIN.1.min(work.1));
    if configured.0 <= work.0 * SHARE && configured.1 <= work.1 * SHARE {
        return Fit { size: configured, min, maximize: false };
    }
    let size = ((work.0 * SHARE).min(configured.0).max(min.0), (work.1 * SHARE).min(configured.1).max(min.1));
    Fit { size, min, maximize: work.0 < MAXIMIZE_BELOW.0 || work.1 < MAXIMIZE_BELOW.1 }
}

/// Sizes the main window for its monitor's work area, then shows it (it is created hidden).
pub fn apply<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>, configured: (f64, f64)) {
    let monitor = window
        .current_monitor()
        .ok()
        .flatten()
        .or_else(|| window.primary_monitor().ok().flatten())
        .or_else(|| window.available_monitors().ok().and_then(|m| m.into_iter().next()));
    if let Some(m) = monitor {
        let scale = m.scale_factor();
        let area = m.work_area();
        let work = (f64::from(area.size.width) / scale, f64::from(area.size.height) / scale);
        // a monitor that reports no usable area keeps the configured window
        if scale > 0.0 && work.0 >= 320.0 && work.1 >= 240.0 {
            let f = fit(configured, work);
            let _ = window.set_min_size(Some(tauri::LogicalSize::new(f.min.0, f.min.1)));
            if f.size != configured {
                let _ = window.set_size(tauri::LogicalSize::new(f.size.0, f.size.1));
                let _ = window.center();
            }
            if f.maximize {
                let _ = window.maximize();
            }
        }
    }
    let _ = window.show();
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIGURED: (f64, f64) = (1440.0, 900.0);

    /// The work areas of a 1920 × 1080 screen at the common scalings, under a 48-pixel taskbar.
    #[test]
    fn the_window_fits_common_scalings() {
        // 100 %: the configured window fits
        let f = fit(CONFIGURED, (1920.0, 1032.0));
        assert_eq!(f, Fit { size: CONFIGURED, min: MIN, maximize: false });
        // 125 %: 1536 × 826 — narrower is not needed, shorter is
        let f = fit(CONFIGURED, (1536.0, 826.0));
        assert!(!f.maximize && f.size.0 == 1440.0 && f.size.1 <= 826.0 && f.size.1 >= MIN.1, "{f:?}");
        // 150 %: 1280 × 688
        let f = fit(CONFIGURED, (1280.0, 688.0));
        assert!(!f.maximize && f.size.0 <= 1280.0 && f.size.1 <= 688.0 && f.size.0 >= MIN.0 && f.size.1 >= MIN.1, "{f:?}");
        // 200 %: 960 × 516, maximized
        let f = fit(CONFIGURED, (960.0, 516.0));
        assert!(f.maximize && f.size.0 <= 960.0 && f.size.1 <= 516.0 && f.min == MIN, "{f:?}");
        // 1366 × 768 at 100 % (a 40-pixel taskbar)
        let f = fit(CONFIGURED, (1366.0, 728.0));
        assert!(!f.maximize && f.size.0 <= 1366.0 && f.size.1 <= 728.0, "{f:?}");
    }

    /// The minimum itself fits the smallest of them under each desktop's panel.
    #[test]
    fn the_minimum_fits_200_percent_under_every_panel() {
        // Windows taskbar (24 logical px at 200 %), GNOME top bar (32), KDE Plasma panel (44)
        for work in [(960.0, 516.0), (960.0, 508.0), (960.0, 496.0)] {
            assert!(MIN.0 <= work.0 && MIN.1 <= work.1, "{work:?}");
            let f = fit(CONFIGURED, work);
            assert!(f.size.0 <= work.0 && f.size.1 <= work.1 && f.min == MIN, "{work:?}: {f:?}");
        }
    }

    /// A screen smaller than the minimum still gets the whole window.
    #[test]
    fn a_tiny_screen_lowers_the_minimum() {
        let f = fit(CONFIGURED, (720.0, 400.0));
        assert!(f.maximize && f.min == (720.0, 400.0) && f.size.0 <= 720.0 && f.size.1 <= 400.0, "{f:?}");
    }

    /// `tauri.conf.json` creates the window hidden (shown by `apply`) with the same minimum.
    #[test]
    fn the_configuration_matches() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let w = &conf["app"]["windows"][0];
        assert_eq!(w["label"], "main");
        assert_eq!((w["minWidth"].as_f64(), w["minHeight"].as_f64()), (Some(MIN.0), Some(MIN.1)));
        assert_eq!(w["visible"], false, "shown by window_fit::apply once sized");
        let configured = (w["width"].as_f64().unwrap(), w["height"].as_f64().unwrap());
        assert!(configured.0 >= MIN.0 && configured.1 >= MIN.1);
    }
}
