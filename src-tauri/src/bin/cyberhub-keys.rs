//! Developer-only credential provisioning tool. Built only with `--features provisioning`;
//! never part of the application or its installers. See docs/PROVISIONING.md.

fn main() {
    std::process::exit(cyber_hub_lib::provision::main());
}
