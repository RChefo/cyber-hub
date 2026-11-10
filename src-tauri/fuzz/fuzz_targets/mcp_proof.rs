#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| cyber_hub_lib::fuzzing::mcp_proof(data));
