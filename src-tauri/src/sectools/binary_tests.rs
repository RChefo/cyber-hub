use std::borrow::Cow;

use super::*;

#[test]
fn hashes_entropy_and_strings() {
    let r = analyze(b"abc").unwrap();
    assert_eq!(r.md5, "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(r.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(r.sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!((r.format.as_str(), r.warnings.len()), ("unknown", 1));
    assert!(analyze(b"").is_err());

    assert_eq!(entropy(&[0u8; 4096]), 0.0);
    let all: Vec<u8> = (0..=255u8).cycle().take(256 * 16).collect();
    assert_eq!(entropy(&all), 8.0);

    // a short ASCII run, then zero padding before the UTF-16 string, as in real files
    let mut blob = b"\x00\x01http://198.51.100.7/payload.bin\x00ab\x00\x00\x00\x00".to_vec();
    blob.extend("C:\\Users\\Public\\run.ps1".encode_utf16().flat_map(u16::to_le_bytes));
    blob.extend([0, 0]);
    let (s, total) = strings(&blob, 10);
    assert_eq!(s, vec!["http://198.51.100.7/payload.bin".to_string(), "C:\\Users\\Public\\run.ps1".to_string()], "ASCII and UTF-16; runs under six characters are left out");
    assert_eq!(total, 2);
}

#[test]
fn imports_become_capabilities_only_when_every_part_is_there() {
    let set = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<BTreeSet<String>>();
    let mut caps = Vec::new();
    capabilities(PE_RULES, &set(&["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "SetWindowsHookExW", "GetAsyncKeyState", "MiniDumpWriteDump"]), &mut caps);
    let ids: Vec<&str> = caps.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, vec!["BIN-INJECTION", "BIN-LSASS-DUMP", "BIN-KEYLOGGING"]);
    assert_eq!(caps[0].evidence, vec!["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]);
    assert_eq!(caps[0].technique, "T1055 Process Injection");

    let mut partial = Vec::new();
    capabilities(PE_RULES, &set(&["VirtualAllocEx", "WriteProcessMemory"]), &mut partial);
    assert!(partial.is_empty(), "allocation and writing alone do not inject");

    let mut elf_caps = Vec::new();
    capabilities(ELF_RULES, &set(&["socket", "connect", "dup2", "execve", "ptrace"]), &mut elf_caps);
    assert_eq!(elf_caps.iter().map(|c| c.id.as_str()).collect::<Vec<_>>(), vec!["BIN-PTRACE", "BIN-SHELL"]);
}

#[test]
fn imphash_follows_pefile() {
    let imp = |dll: &'static str, name: &'static str, ordinal: u16| goblin::pe::import::Import { name: Cow::Borrowed(name), dll, ordinal, offset: 0, rva: 0, size: 0 };
    let imports = vec![imp("KERNEL32.dll", "GetProcAddress", 0), imp("KERNEL32.dll", "LoadLibraryA", 0), imp("WS2_32.dll", "ORDINAL 115", 115)];
    // hashlib.md5(b"kernel32.getprocaddress,kernel32.loadlibrarya,ws2_32.ord115")
    assert_eq!(imphash(&imports), "4b01078734e35448a0c24ccebd0e84ec");
    assert_eq!(imphash(&[]), "");
}

#[test]
fn a_minimal_elf_with_an_executable_stack() {
    let mut f = Vec::new();
    f.extend([0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    f.extend(2u16.to_le_bytes()); // ET_EXEC
    f.extend(62u16.to_le_bytes()); // x86-64
    f.extend(1u32.to_le_bytes());
    f.extend(0x40_0078u64.to_le_bytes());
    f.extend(64u64.to_le_bytes()); // program headers
    f.extend(0u64.to_le_bytes()); // no section headers
    f.extend(0u32.to_le_bytes());
    for v in [64u16, 56, 2, 64, 0, 0] {
        f.extend(v.to_le_bytes());
    }
    for (ty, flags) in [(1u32, 7u32), (0x6474_e551, 7)] {
        f.extend(ty.to_le_bytes());
        f.extend(flags.to_le_bytes());
        for v in [0u64, 0x40_0000, 0x40_0000, 0xb0, 0xb0, 0x1000] {
            f.extend(v.to_le_bytes());
        }
    }
    let r = analyze(&f).unwrap();
    assert_eq!((r.format.as_str(), r.machine.as_str(), r.kind.as_str()), ("ELF64", "x86-64", "executable"));
    let has = |name: &str| r.hardening.iter().find(|h| h.name == name).map(|h| h.present);
    assert_eq!((has("PIE"), has("NX stack")), (Some(false), Some(false)));
    assert!(r.capabilities.iter().any(|c| c.id == "BIN-WX-SEGMENT"));
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

/// The test program itself: a real PE on Windows, a real ELF elsewhere.
#[test]
fn the_running_test_binary() {
    let data = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let r = analyze(&data).unwrap();
    if cfg!(windows) {
        assert!(r.format.starts_with("PE"), "{}", r.format);
        assert!(r.kind.starts_with("executable"));
        assert_eq!(r.imphash.len(), 32);
        assert!(r.libraries.iter().any(|l| l.name.eq_ignore_ascii_case("kernel32.dll")), "{:?}", r.libraries.iter().map(|l| &l.name).collect::<Vec<_>>());
        let aslr = r.hardening.iter().find(|h| h.name == "ASLR").unwrap();
        assert!(aslr.present, "Rust links with DYNAMIC_BASE");
        assert!(r.sections.iter().any(|s| s.name == ".text" && s.flags == "r-x"));
    } else {
        assert!(r.format.starts_with("ELF"), "{}", r.format);
        assert!(r.hardening.iter().any(|h| h.name == "NX stack" && h.present));
    }
    assert!(r.strings_total > 100);
    assert!(r.capabilities.iter().all(|c| !c.id.is_empty()));
}

#[test]
fn damaged_headers_do_not_stop_the_triage() {
    let mut f = b"MZ".to_vec();
    f.extend([0xffu8; 200]);
    let r = analyze(&f).unwrap();
    assert!(r.warnings[0].starts_with("Not a valid PE file"), "{:?}", r.warnings);
    assert_eq!(r.sha256.len(), 64);
    let mut e = b"\x7fELF".to_vec();
    e.extend([2u8, 1, 1]);
    assert!(analyze(&e).unwrap().warnings[0].starts_with("Not a valid ELF file"));
}
