// SPDX-License-Identifier: Apache-2.0
fn main() {
    // `cyberhub-mcp` is a `[[bin]]` of this crate: the Tauri bundler ships every binary of the
    // crate next to the app, so it needs no `bundle.externalBin` entry (an extra sidecar copy made
    // the MSI contain the same file twice; see docs/PLATFORMS.md).
    tauri_build::build()
}
