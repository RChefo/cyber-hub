//! Static file triage (docs/UTILITIES.md, "File triage"): what a PE or ELF file is and what it
//! can do, read without running it. Hashes (with the PE import hash), sections with entropy,
//! imports, hardening flags, packer traces, capabilities inferred from imported functions (with
//! their MITRE ATT&CK technique) and printable strings. Capabilities are what the imports allow,
//! not proof of intent: legitimate programs import many of the same functions.

use std::collections::{BTreeMap, BTreeSet};

use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STRINGS: usize = 3000;
const MAX_IMPORTS: usize = 5000;
const MIN_STRING: usize = 6;

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub name: String,
    pub size: u64,
    pub virtual_size: u64,
    pub entropy: f64,
    /// r, w and x
    pub flags: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Library {
    pub name: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Hardening {
    pub name: String,
    pub present: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    /// high, medium, low or info
    pub severity: String,
    pub title: String,
    pub detail: String,
    /// "T1055 Process Injection", or ""
    pub technique: String,
    /// the imports or traces behind it
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// PE32, PE32+, ELF32, ELF64 or unknown
    pub format: String,
    pub machine: String,
    /// executable, DLL, driver, shared library, position-independent executable, relocatable…
    pub kind: String,
    pub size: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    /// PE import hash (MD5 of the normalized import list), as pefile computes it
    pub imphash: String,
    /// PE link time or ELF interpreter
    pub compiled: String,
    pub interpreter: String,
    pub entropy: f64,
    pub dotnet: bool,
    pub sections: Vec<Section>,
    pub libraries: Vec<Library>,
    pub exports: Vec<String>,
    pub hardening: Vec<Hardening>,
    pub capabilities: Vec<Capability>,
    /// printable ASCII and UTF-16 strings of at least six characters (at most 3,000)
    pub strings: Vec<String>,
    pub strings_total: usize,
    /// bytes after the last section (PE)
    pub overlay: u64,
    pub warnings: Vec<String>,
}

/// Shannon entropy in bits per byte (0 to 8).
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    let e: f64 = counts.iter().filter(|c| **c > 0).map(|c| {
        let p = *c as f64 / n;
        -p * p.log2()
    }).sum();
    (e * 1000.0).round() / 1000.0
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Printable ASCII and UTF-16LE runs.
pub fn strings(data: &[u8], limit: usize) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut total = 0usize;
    let printable = |b: u8| (0x20..0x7f).contains(&b) || b == b'\t';
    let mut push = |s: String, out: &mut Vec<String>| {
        total += 1;
        if out.len() < limit {
            out.push(s.chars().take(300).collect());
        }
    };
    let mut cur = Vec::new();
    for &b in data {
        if printable(b) {
            cur.push(b);
        } else {
            if cur.len() >= MIN_STRING {
                push(String::from_utf8_lossy(&cur).into_owned(), &mut out);
            }
            cur.clear();
        }
    }
    if cur.len() >= MIN_STRING {
        push(String::from_utf8_lossy(&cur).into_owned(), &mut out);
    }
    for start in 0..2 {
        let mut cur16: Vec<u8> = Vec::new();
        let mut i = start;
        while i + 1 < data.len() {
            let (lo, hi) = (data[i], data[i + 1]);
            if hi == 0 && printable(lo) {
                cur16.push(lo);
            } else {
                if cur16.len() >= MIN_STRING {
                    push(String::from_utf8_lossy(&cur16).into_owned(), &mut out);
                }
                cur16.clear();
            }
            i += 2;
        }
        if cur16.len() >= MIN_STRING {
            push(String::from_utf8_lossy(&cur16).into_owned(), &mut out);
        }
    }
    (out, total)
}

/// Imported functions that, together, allow an action (any one of each group).
struct Rule {
    id: &'static str,
    severity: &'static str,
    title: &'static str,
    detail: &'static str,
    technique: &'static str,
    /// every group needs one of its functions (prefix match, ignoring an A/W/Ex suffix)
    groups: &'static [&'static [&'static str]],
}

const PE_RULES: &[Rule] = &[
    Rule { id: "BIN-INJECTION", severity: "high", title: "Can inject code into other processes", detail: "It imports functions to allocate and write memory in another process and start a thread there.", technique: "T1055 Process Injection", groups: &[&["VirtualAllocEx", "NtAllocateVirtualMemory"], &["WriteProcessMemory", "NtWriteVirtualMemory"], &["CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "SetThreadContext"]] },
    Rule { id: "BIN-HOLLOWING", severity: "high", title: "Can replace the code of a process it starts", detail: "It imports functions to unmap a process image and redirect its main thread, as process hollowing does.", technique: "T1055.012 Process Injection: Process Hollowing", groups: &[&["NtUnmapViewOfSection", "ZwUnmapViewOfSection"], &["SetThreadContext", "Wow64SetThreadContext"], &["ResumeThread"]] },
    Rule { id: "BIN-LSASS-DUMP", severity: "high", title: "Can write process memory dumps", detail: "It imports MiniDumpWriteDump, which credential dumpers use on lsass.exe.", technique: "T1003.001 OS Credential Dumping: LSASS Memory", groups: &[&["MiniDumpWriteDump"]] },
    Rule { id: "BIN-KEYLOGGING", severity: "medium", title: "Can record keystrokes", detail: "It imports a keyboard hook or key-state function together with hook installation.", technique: "T1056.001 Input Capture: Keylogging", groups: &[&["SetWindowsHookEx"], &["GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "CallNextHookEx"]] },
    Rule { id: "BIN-TOKEN", severity: "medium", title: "Can change or impersonate access tokens", detail: "It imports functions to enable privileges or impersonate another user's token.", technique: "T1134 Access Token Manipulation", groups: &[&["AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "DuplicateTokenEx", "SetThreadToken", "CreateProcessWithToken"]] },
    Rule { id: "BIN-SERVICE", severity: "low", title: "Can create Windows services", detail: "It imports the service control manager functions that install services.", technique: "T1543.003 Create or Modify System Process: Windows Service", groups: &[&["CreateService"]] },
    Rule { id: "BIN-DOWNLOAD", severity: "medium", title: "Can download files", detail: "It imports URLDownloadToFile or HTTP client functions.", technique: "T1105 Ingress Tool Transfer", groups: &[&["URLDownloadToFile", "InternetOpenUrl", "HttpSendRequest", "WinHttpSendRequest", "InternetReadFile"]] },
    Rule { id: "BIN-CLIPBOARD", severity: "low", title: "Can read the clipboard", detail: "It imports GetClipboardData.", technique: "T1115 Clipboard Data", groups: &[&["GetClipboardData"]] },
    Rule { id: "BIN-SCREENSHOT", severity: "low", title: "Can capture the screen", detail: "It imports screen device contexts and BitBlt.", technique: "T1113 Screen Capture", groups: &[&["GetDesktopWindow", "GetDC", "CreateDC"], &["BitBlt"]] },
    Rule { id: "BIN-ANTI-DEBUG", severity: "low", title: "Checks for a debugger", detail: "It imports debugger checks; protected and malicious programs use them to hide their behaviour.", technique: "T1622 Debugger Evasion", groups: &[&["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"]] },
];

const ELF_RULES: &[Rule] = &[
    Rule { id: "BIN-PTRACE", severity: "medium", title: "Can attach to other processes (ptrace)", detail: "It imports ptrace, which debuggers use and which injects code into running processes.", technique: "T1055.008 Process Injection: Ptrace System Calls", groups: &[&["ptrace"]] },
    Rule { id: "BIN-SHELL", severity: "medium", title: "Connects a socket to a shell", detail: "It imports socket functions, dup2 and exec, the parts of a reverse or bind shell.", technique: "T1059.004 Command and Scripting Interpreter: Unix Shell", groups: &[&["connect", "accept", "bind"], &["dup2", "dup3"], &["execve", "execl", "execvp", "execlp", "system"]] },
    Rule { id: "BIN-SETUID", severity: "low", title: "Changes its user or group", detail: "It imports setuid or setgid.", technique: "T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid", groups: &[&["setuid", "setreuid", "setresuid", "setgid", "setresgid"]] },
    Rule { id: "BIN-DLOPEN", severity: "info", title: "Loads code at run time", detail: "It imports dlopen and dlsym.", technique: "T1129 Shared Modules", groups: &[&["dlopen"], &["dlsym"]] },
];

fn base(name: &str) -> String {
    let n = name.trim_start_matches('_');
    let n = n.strip_suffix("Ex").unwrap_or(n);
    let n = n.strip_suffix('A').or_else(|| n.strip_suffix('W')).unwrap_or(n);
    let n = n.strip_suffix("Ex").unwrap_or(n);
    n.to_string()
}

fn capabilities(rules: &[Rule], imported: &BTreeSet<String>, out: &mut Vec<Capability>) {
    let normalized: BTreeMap<String, &String> = imported.iter().map(|f| (base(f).to_ascii_lowercase(), f)).collect();
    for r in rules {
        let mut evidence = Vec::new();
        let all = r.groups.iter().all(|group| {
            let hit = group.iter().find_map(|want| normalized.get(&base(want).to_ascii_lowercase()));
            if let Some(f) = hit {
                evidence.push((*f).clone());
            }
            hit.is_some()
        });
        if all {
            out.push(Capability { id: r.id.into(), severity: r.severity.into(), title: r.title.into(), detail: r.detail.into(), technique: r.technique.into(), evidence });
        }
    }
}

/// Section names that packers and protectors leave behind.
const PACKERS: &[(&str, &str)] = &[
    ("upx", "UPX"), (".aspack", "ASPack"), (".adata", "ASPack"), (".mpress", "MPRESS"), (".petite", "Petite"), (".themida", "Themida"), (".winlice", "WinLicense"), (".vmp", "VMProtect"),
    (".enigma", "Enigma Protector"), (".nsp", "NsPack"), ("pec2", "PECompact"), (".packed", "a packer"), (".perplex", "Perplex"), (".spack", "Simple Pack"),
];

fn packer(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    PACKERS.iter().find(|(p, _)| n.starts_with(p)).map(|(_, tool)| *tool)
}

fn finish_sections(sections: &mut [Section], caps: &mut Vec<Capability>) {
    let mut packed = BTreeSet::new();
    for s in sections.iter_mut() {
        if let Some(p) = packer(&s.name) {
            s.note = format!("{p} section");
            packed.insert(p);
        } else if s.flags.contains('x') && s.entropy >= 7.2 {
            s.note = "executable and highly random: packed or encrypted code".into();
        }
        if s.flags.contains('w') && s.flags.contains('x') && s.note.is_empty() {
            s.note = "writable and executable".into();
        }
    }
    if !packed.is_empty() {
        caps.push(Capability { id: "BIN-PACKED".into(), severity: "medium".into(), title: "Packed or protected".into(), detail: format!("Section names of {} were found: the real code is unpacked at run time, which hides it from static analysis.", packed.iter().copied().collect::<Vec<_>>().join(", ")), technique: "T1027.002 Obfuscated Files or Information: Software Packing".into(), evidence: sections.iter().filter(|s| packer(&s.name).is_some()).map(|s| s.name.clone()).collect() });
    } else if sections.iter().any(|s| s.flags.contains('x') && s.entropy >= 7.2) {
        caps.push(Capability { id: "BIN-HIGH-ENTROPY".into(), severity: "low".into(), title: "Executable section with random-looking content".into(), detail: "An executable section has an entropy of 7.2 bits per byte or more, typical of packed or encrypted code.".into(), technique: "T1027.002 Obfuscated Files or Information: Software Packing".into(), evidence: sections.iter().filter(|s| s.flags.contains('x') && s.entropy >= 7.2).map(|s| format!("{} ({})", s.name, s.entropy)).collect() });
    }
    let wx: Vec<String> = sections.iter().filter(|s| s.flags.contains('w') && s.flags.contains('x')).map(|s| s.name.clone()).collect();
    if !wx.is_empty() {
        caps.push(Capability { id: "BIN-WX-SECTION".into(), severity: "low".into(), title: "Writable and executable section".into(), detail: "Code that can be rewritten while it runs; unpackers and self-modifying code need it, ordinary compilers do not produce it.".into(), technique: String::new(), evidence: wx });
    }
}

fn section_name(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw).trim_end_matches('\0').to_string()
}

fn pe(data: &[u8], p: &goblin::pe::PE, r: &mut Report) {
    use goblin::pe::characteristic::IMAGE_FILE_DLL;
    use goblin::pe::section_table::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};
    r.format = if p.is_64 { "PE32+".into() } else { "PE32".into() };
    let coff = &p.header.coff_header;
    r.machine = match coff.machine {
        0x14c => "x86".into(),
        0x8664 => "x64".into(),
        0xaa64 => "ARM64".into(),
        0x1c0 | 0x1c4 => "ARM".into(),
        m => format!("0x{m:04x}"),
    };
    let subsystem = p.header.optional_header.as_ref().map(|o| o.windows_fields.subsystem).unwrap_or(0);
    r.kind = if coff.characteristics & IMAGE_FILE_DLL != 0 {
        "DLL".into()
    } else if subsystem == 1 {
        "driver".into()
    } else if subsystem == 2 {
        "executable (GUI)".into()
    } else {
        "executable (console)".into()
    };
    let ts = coff.time_date_stamp;
    r.compiled = chrono::DateTime::from_timestamp(i64::from(ts), 0).map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap_or_default();
    let mut caps = Vec::new();
    // sections
    let mut end_of_sections = 0u64;
    // the PE format allows at most 96 sections; a file claiming more is not read past them
    for s in p.sections.iter().take(96) {
        let start = s.pointer_to_raw_data as usize;
        let size = s.size_of_raw_data as usize;
        let body = data.get(start..start.saturating_add(size).min(data.len())).unwrap_or(&[]);
        end_of_sections = end_of_sections.max(u64::from(s.pointer_to_raw_data) + u64::from(s.size_of_raw_data));
        let c = s.characteristics;
        let flags = format!("{}{}{}", if c & IMAGE_SCN_MEM_READ != 0 { "r" } else { "-" }, if c & IMAGE_SCN_MEM_WRITE != 0 { "w" } else { "-" }, if c & IMAGE_SCN_MEM_EXECUTE != 0 { "x" } else { "-" });
        r.sections.push(Section { name: section_name(&s.name), size: u64::from(s.size_of_raw_data), virtual_size: u64::from(s.virtual_size), entropy: entropy(body), flags, note: String::new() });
    }
    // imports
    let mut by_lib: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut imported = BTreeSet::new();
    for (n, imp) in p.imports.iter().enumerate() {
        if n >= MAX_IMPORTS {
            r.warnings.push(format!("Only the first {MAX_IMPORTS} imports are listed"));
            break;
        }
        let name = if imp.name.starts_with("ORDINAL ") { format!("ord{}", imp.ordinal) } else { imp.name.to_string() };
        imported.insert(name.clone());
        by_lib.entry(imp.dll.to_string()).or_default().push(name);
    }
    r.libraries = by_lib.into_iter().map(|(name, mut functions)| {
        functions.sort();
        functions.dedup();
        Library { name, functions }
    }).collect();
    r.imphash = imphash(&p.imports);
    r.exports = p.exports.iter().filter_map(|e| e.name.map(String::from)).take(200).collect();
    let dirs = p.header.optional_header.as_ref().map(|o| o.data_directories);
    r.dotnet = dirs.as_ref().and_then(|d| d.get_clr_runtime_header()).is_some_and(|c| c.virtual_address != 0);
    let signed = dirs.as_ref().and_then(|d| d.get_certificate_table()).is_some_and(|c| c.virtual_address != 0 && c.size != 0);
    // hardening
    let dll = p.header.optional_header.as_ref().map(|o| o.windows_fields.dll_characteristics).unwrap_or(0);
    let flag = |bit: u16| dll & bit != 0;
    r.hardening = vec![
        Hardening { name: "ASLR".into(), present: flag(0x0040), detail: "DYNAMIC_BASE: loaded at a random address".into() },
        Hardening { name: "DEP".into(), present: flag(0x0100), detail: "NX_COMPAT: data pages are not executable".into() },
        Hardening { name: "Control Flow Guard".into(), present: flag(0x4000), detail: "GUARD_CF: indirect calls are checked".into() },
        Hardening { name: "High-entropy ASLR".into(), present: !p.is_64 || flag(0x0020), detail: "HIGH_ENTROPY_VA (64-bit)".into() },
        Hardening { name: "Embedded signature".into(), present: signed, detail: "An Authenticode signature is embedded (ExploitX does not verify it); Windows system files are usually signed through catalogs instead".into() },
    ];
    // overlay: data after the last section, other than the signature
    let cert = dirs.as_ref().and_then(|d| d.get_certificate_table()).map(|c| u64::from(c.size)).unwrap_or(0);
    r.overlay = (data.len() as u64).saturating_sub(end_of_sections).saturating_sub(cert);
    capabilities(PE_RULES, &imported, &mut caps);
    if imported.is_empty() && !r.dotnet {
        caps.push(Capability { id: "BIN-NO-IMPORTS".into(), severity: "medium".into(), title: "No imports".into(), detail: "The file imports no functions, so it must find them at run time, as packed programs and shellcode loaders do.".into(), technique: "T1027.007 Obfuscated Files or Information: Dynamic API Resolution".into(), evidence: Vec::new() });
    } else if imported.len() <= 6 && !r.dotnet && imported.iter().any(|f| base(f).eq_ignore_ascii_case("GetProcAddress")) {
        caps.push(Capability { id: "BIN-FEW-IMPORTS".into(), severity: "low".into(), title: "Very few imports, among them GetProcAddress".into(), detail: "The file imports almost nothing but the means to look functions up, typical of packed programs.".into(), technique: "T1027.007 Obfuscated Files or Information: Dynamic API Resolution".into(), evidence: imported.iter().cloned().collect() });
    }
    if ts != 0 && (ts < 631_152_000 || i64::from(ts) > chrono::Utc::now().timestamp() + 86_400) && !r.dotnet {
        r.warnings.push(format!("The link time ({}) is before 1990 or in the future: it was probably changed, or the build is reproducible", r.compiled));
    }
    if r.overlay > 0 {
        r.warnings.push(format!("{} bytes follow the last section (an overlay): installers keep their payload there, and so do droppers", r.overlay));
    }
    finish_sections(&mut r.sections, &mut caps);
    r.capabilities = caps;
}

/// pefile's imphash: lower-case "library.function" pairs (library without .dll/.ocx/.sys, ordinals
/// as "ordN"), joined with commas, MD5.
pub fn imphash(imports: &[goblin::pe::import::Import]) -> String {
    if imports.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = imports
        .iter()
        .map(|i| {
            let lib = i.dll.to_ascii_lowercase();
            let lib = [".dll", ".ocx", ".sys"].iter().find_map(|e| lib.strip_suffix(e)).unwrap_or(&lib).to_string();
            let func = if i.name.starts_with("ORDINAL ") { format!("ord{}", i.ordinal) } else { i.name.to_ascii_lowercase() };
            format!("{lib}.{func}")
        })
        .collect();
    hex(&Md5::digest(parts.join(",").as_bytes()))
}

fn elf(data: &[u8], e: &goblin::elf::Elf, r: &mut Report) {
    use goblin::elf::dynamic::{DF_1_NOW, DF_BIND_NOW, DT_FLAGS, DT_FLAGS_1, DT_RPATH, DT_RUNPATH};
    use goblin::elf::header::{EM_386, EM_AARCH64, EM_ARM, EM_MIPS, EM_PPC64, EM_RISCV, EM_X86_64, ET_CORE, ET_DYN, ET_EXEC, ET_REL};
    use goblin::elf::program_header::{PF_W, PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
    r.format = if e.is_64 { "ELF64".into() } else { "ELF32".into() };
    r.machine = match e.header.e_machine {
        EM_X86_64 => "x86-64".into(),
        EM_386 => "x86".into(),
        EM_AARCH64 => "AArch64".into(),
        EM_ARM => "ARM".into(),
        EM_MIPS => "MIPS".into(),
        EM_PPC64 => "PowerPC 64".into(),
        EM_RISCV => "RISC-V".into(),
        m => format!("machine {m}"),
    };
    r.interpreter = e.interpreter.unwrap_or("").to_string();
    r.kind = match e.header.e_type {
        ET_EXEC => "executable".into(),
        ET_DYN if e.interpreter.is_some() => "position-independent executable".into(),
        ET_DYN => "shared library".into(),
        ET_REL => "relocatable object".into(),
        ET_CORE => "core dump".into(),
        t => format!("type {t}"),
    };
    let mut caps = Vec::new();
    for sh in &e.section_headers {
        let name = e.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        if sh.sh_type == goblin::elf::section_header::SHT_NOBITS || name.is_empty() {
            continue;
        }
        let start = sh.sh_offset as usize;
        let body = data.get(start..start.saturating_add(sh.sh_size as usize).min(data.len())).unwrap_or(&[]);
        let flags = format!("r{}{}", if sh.is_writable() { "w" } else { "-" }, if sh.is_executable() { "x" } else { "-" });
        r.sections.push(Section { name, size: sh.sh_size, virtual_size: sh.sh_size, entropy: entropy(body), flags, note: String::new() });
    }
    let mut imported = BTreeSet::new();
    for sym in e.dynsyms.iter().filter(|s| s.is_import()) {
        if let Some(n) = e.dynstrtab.get_at(sym.st_name) {
            if imported.len() < MAX_IMPORTS {
                imported.insert(n.split('@').next().unwrap_or(n).to_string());
            }
        }
    }
    r.libraries = e.libraries.iter().map(|l| Library { name: l.to_string(), functions: Vec::new() }).collect();
    if !imported.is_empty() {
        r.libraries.push(Library { name: "imported symbols".into(), functions: imported.iter().cloned().collect() });
    }
    r.exports = e.dynsyms.iter().filter(|s| !s.is_import() && s.st_name != 0).filter_map(|s| e.dynstrtab.get_at(s.st_name).map(String::from)).take(200).collect();
    let stack_x = e.program_headers.iter().find(|p| p.p_type == PT_GNU_STACK).is_some_and(|p| p.p_flags & PF_X != 0);
    let relro = e.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);
    let dyn_tags: Vec<(u64, u64)> = e.dynamic.as_ref().map(|d| d.dyns.iter().map(|x| (x.d_tag, x.d_val)).collect()).unwrap_or_default();
    let bind_now = dyn_tags.iter().any(|(t, v)| (*t == DT_FLAGS && v & DF_BIND_NOW != 0) || (*t == DT_FLAGS_1 && v & DF_1_NOW != 0));
    let rpath = dyn_tags.iter().any(|(t, _)| *t == DT_RPATH || *t == DT_RUNPATH);
    let canary = imported.contains("__stack_chk_fail");
    let fortify = imported.iter().any(|f| f.starts_with("__") && f.ends_with("_chk") && f != "__stack_chk_fail");
    let stripped = !e.section_headers.iter().any(|s| s.sh_type == goblin::elf::section_header::SHT_SYMTAB);
    r.hardening = vec![
        Hardening { name: "PIE".into(), present: e.header.e_type == ET_DYN, detail: "loaded at a random address".into() },
        Hardening { name: "NX stack".into(), present: !stack_x, detail: "the stack is not executable".into() },
        Hardening { name: "RELRO".into(), present: relro, detail: if bind_now { "full: relocations read-only after start".into() } else { "partial".into() } },
        Hardening { name: "Stack canary".into(), present: canary, detail: "__stack_chk_fail is imported".into() },
        Hardening { name: "FORTIFY_SOURCE".into(), present: fortify, detail: "checked versions of string functions".into() },
        Hardening { name: "No RPATH or RUNPATH".into(), present: !rpath, detail: "a library search path in the binary can let a writable folder supply libraries".into() },
        Hardening { name: "Symbols kept".into(), present: !stripped, detail: "stripped binaries are harder to analyse".into() },
    ];
    let rwx: Vec<String> = e.program_headers.iter().filter(|p| p.p_type == PT_LOAD && p.p_flags & PF_W != 0 && p.p_flags & PF_X != 0).map(|p| format!("LOAD at 0x{:x}", p.p_vaddr)).collect();
    if !rwx.is_empty() {
        caps.push(Capability { id: "BIN-WX-SEGMENT".into(), severity: "low".into(), title: "Writable and executable segment".into(), detail: "A loadable segment is both writable and executable; packers and injected code need this, ordinary toolchains do not produce it.".into(), technique: String::new(), evidence: rwx });
    }
    capabilities(ELF_RULES, &imported, &mut caps);
    finish_sections(&mut r.sections, &mut caps);
    r.capabilities = caps;
}

/// Triage of a file's bytes; `Err` only for an empty file.
pub fn analyze(data: &[u8]) -> Result<Report, String> {
    if data.is_empty() {
        return Err("The file is empty".into());
    }
    let mut r = Report {
        size: data.len() as u64,
        md5: hex(&Md5::digest(data)),
        sha1: hex(&Sha1::digest(data)),
        sha256: hex(&Sha256::digest(data)),
        entropy: entropy(data),
        format: "unknown".into(),
        ..Default::default()
    };
    // dispatch on the signature (goblin's Object needs every format compiled in)
    if data.starts_with(b"MZ") {
        match goblin::pe::PE::parse(data) {
            Ok(p) => pe(data, &p, &mut r),
            Err(e) => r.warnings.push(format!("Not a valid PE file ({e}): only hashes and strings are shown")),
        }
    } else if data.starts_with(b"\x7fELF") {
        match goblin::elf::Elf::parse(data) {
            Ok(e) => elf(data, &e, &mut r),
            Err(e) => r.warnings.push(format!("Not a valid ELF file ({e}): only hashes and strings are shown")),
        }
    } else {
        r.warnings.push("Not a PE or ELF file: only hashes and strings are shown".into());
    }
    let (s, total) = strings(data, MAX_STRINGS);
    r.strings = s;
    r.strings_total = total;
    r.capabilities.sort_by_key(|c| ["high", "medium", "low", "info"].iter().position(|x| *x == c.severity).unwrap_or(4));
    Ok(r)
}

#[cfg(test)]
#[path = "binary_tests.rs"]
mod tests;
