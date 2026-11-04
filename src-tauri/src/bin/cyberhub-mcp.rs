//! MCP server for Cyber Hub (stdio). Launched by MCP clients such as Claude Code or Claude
//! Desktop; talks to the running Cyber Hub app over an authenticated loopback bridge.
//! See docs/MCP.md.

fn main() {
    std::process::exit(cyber_hub_lib::mcp::server::main());
}
