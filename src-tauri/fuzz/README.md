# Fuzzing Cyber Hub's parsers

Coverage-guided fuzz targets (cargo-fuzz, libFuzzer) for the parsers of untrusted input. They call
`cyber_hub_lib::fuzzing`, which exists only with the `fuzzing` feature: application builds and
installers never include it. The deterministic hostile-input sweep (`src/hostile_tests.rs`) runs
in every test run; these targets search further and are run by hand.

Requirements: Linux, a nightly toolchain, `cargo install cargo-fuzz`, and the Tauri build
dependencies (`libwebkit2gtk-4.1-dev` and the others listed in the CI workflow).

```sh
cd src-tauri/fuzz
cargo +nightly fuzz build --release            # once, with network access
# then without network, each target for a bounded time and memory
cargo +nightly fuzz run yaml -- -max_total_time=300 -rss_limit_mb=2048 -timeout=10
```

Targets: `yaml`, `sigma`, `events`, `evtx`, `pcap`, `scan_import`, `sbom`, `lockfiles`, `apisec`,
`osint_import`, `iac`, `binary`, `mcp_proof`. A crash leaves its input in `artifacts/<target>/`:
fix the parser, then keep the input as a regression test next to it (never commit real data).

Seed each target's `corpus/<target>/` with generated inputs, never real files.
* The text fixtures of `src/hostile_tests.rs` suit most targets.
* `evtx` needs a binary seed, such as the file built by `sample()` in `src/sectools/evtx_tests.rs`. Without one it barely gets past the file signature.
