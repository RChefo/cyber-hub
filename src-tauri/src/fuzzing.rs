// SPDX-License-Identifier: Apache-2.0
//! Entry points for coverage-guided fuzzing (`src-tauri/fuzz`, cargo-fuzz). Compiled only with the
//! `fuzzing` feature, which application builds and installers never enable. Each function feeds
//! arbitrary bytes to one parser of untrusted input and ignores the result: a parser may refuse
//! anything, but must not panic, overflow its stack, hang or exhaust memory.

fn text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

pub fn yaml(data: &[u8]) {
    let _ = crate::yaml::parse_documents(&text(data));
}

pub fn sigma(data: &[u8]) {
    let _ = crate::detection::sigma::read(&text(data));
}

pub fn events(data: &[u8]) {
    let _ = crate::detection::events::read(data);
}

pub fn evtx(data: &[u8]) {
    let _ = crate::sectools::evtx::read(data, |_| {});
    let _ = crate::sectools::winevents::analyze(data);
}

pub fn pcap(data: &[u8]) {
    let _ = crate::sectools::pcap::analyze(data);
}

pub fn scan_import(data: &[u8]) {
    let t = text(data);
    let _ = crate::workspace::scan_import::parse(&t);
}

pub fn sbom(data: &[u8]) {
    let _ = crate::workspace::sbom::parse(&text(data));
}

pub fn lockfiles(data: &[u8]) {
    let t = text(data);
    for name in ["package-lock.json", "Cargo.lock", "go.sum", "requirements.txt", "poetry.lock", "Gemfile.lock", "composer.lock", "pnpm-lock.yaml", "yarn.lock", "Pipfile.lock"] {
        let _ = crate::workspace::lockfiles::parse(name, &t);
    }
}

pub fn apisec(data: &[u8]) {
    let _ = crate::workspace::apisec::parse(&text(data));
}

pub fn osint_import(data: &[u8]) {
    let _ = crate::osint::io::parse(data, "json");
    let _ = crate::osint::io::parse(data, "graphml");
}

pub fn iac(data: &[u8]) {
    let t = text(data);
    for (file, hint) in [("main.tf", ""), ("template.json", ""), ("stack.yaml", "")] {
        let _ = crate::sectools::iac::analyze(file, &t, hint);
    }
    for (file, hint) in [("Dockerfile", ""), ("deploy.yaml", "")] {
        let _ = crate::sectools::containers::analyze(file, &t, hint);
    }
}

pub fn binary(data: &[u8]) {
    let _ = crate::sectools::binary::analyze(data);
}

pub fn mcp_proof(data: &[u8]) {
    let _ = crate::mcp::proto::verify(b"0123456789abcdef0123456789abcdef", "client", "a", "b", &text(data));
}
