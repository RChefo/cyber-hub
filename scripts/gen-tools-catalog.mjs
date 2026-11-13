// Generates src-tauri/catalog/tools.json
import { writeFileSync } from "node:fs";

const ALL = ["windows", "macos", "linux"];
const UNIX = ["macos", "linux"];
const LINUX = ["linux"];

const PY = { name: "Python 3", binaries: ["python3", "python", "py"] };
const RUBY = { name: "Ruby", binaries: ["ruby"] };
const PERL = { name: "Perl", binaries: ["perl"] };
const JAVA = { name: "Java (JDK/JRE)", binaries: ["java"] };
const BASH = { name: "Bash", binaries: ["bash"] };
const GOLANG = { name: "Go toolchain (for go install)", binaries: ["go"], optional: true };

const winget = (id) => ({
  os: ["windows"],
  manager: "winget",
  args: ["install", "--id", id, "-e", "--accept-source-agreements", "--accept-package-agreements", "--disable-interactivity"],
});
const brew = (f) => ({ os: ["macos"], manager: "brew", args: ["install", f] });
const cask = (f) => ({ os: ["macos"], manager: "brew", args: ["install", "--cask", f] });
const pipx = (p) => ({ os: ALL, manager: "pipx", args: ["install", p] });
const go = (m) => ({ os: ALL, manager: "go", args: ["install", "-v", m] });

const ex = (title, command, description) => ({ title, command, description });

const tools = [];
function tool(o) {
  const t = {
    id: o.id,
    name: o.name,
    category: o.category,
    description: o.description,
    website: o.website,
  };
  if (o.docs) t.docs = o.docs;
  t.os = o.os;
  t.kind = o.kind ?? "cli";
  t.tags = o.tags;
  if (t.kind !== "web" && t.kind !== "script") {
    if (!o.detect) throw new Error(`missing detect for ${o.id}`);
    t.detect = o.detect;
  }
  t.install = o.install;
  t.managed = o.managed ?? [];
  t.dependencies = o.dependencies ?? [];
  t.commands = o.commands;
  t.requiresScope = o.requiresScope ?? false;
  if (o.builder) t.builder = o.builder;
  tools.push(t);
}

const categories = [
  { id: "web", name: "Web Application Security", icon: "globe", description: "Intercepting proxies, scanners, fuzzers and injection testing for web apps and APIs." },
  { id: "network", name: "Network Security", icon: "network", description: "Port scanning, packet capture and low-level network diagnostics." },
  { id: "osint", name: "OSINT", icon: "eye", description: "Open-source intelligence gathering on organizations, people and infrastructure." },
  { id: "recon", name: "Reconnaissance", icon: "radar", description: "Attack-surface mapping: subdomains, DNS and technology fingerprinting." },
  { id: "vuln", name: "Vulnerability Assessment", icon: "shield-alert", description: "Vulnerability scanners and exploit references for known weaknesses." },
  { id: "password", name: "Password Auditing", icon: "key-round", description: "Hash cracking, credential strength auditing and wordlist generation." },
  { id: "forensics", name: "Digital Forensics", icon: "microscope", description: "Disk, memory and file forensics plus metadata analysis." },
  { id: "malware", name: "Malware Analysis", icon: "bug", description: "Static analysis, signature matching and capability detection for suspicious files." },
  { id: "wireless", name: "Wireless Security", icon: "wifi", description: "Wi-Fi and wireless protocol assessment and monitoring." },
  { id: "cloud", name: "Cloud Security", icon: "cloud", description: "Cloud posture assessment, container and IaC scanning." },
  { id: "reversing", name: "Reverse Engineering", icon: "cpu", description: "Disassemblers, decompilers and debuggers for binaries and apps." },
  { id: "crypto", name: "Cryptography", icon: "lock", description: "TLS configuration testing, certificates and data transformation." },
  { id: "linux", name: "Linux Security", icon: "terminal", description: "Host hardening audits, rootkit detection and privilege-escalation review." },
  { id: "ad", name: "Active Directory Security", icon: "building-2", description: "Active Directory enumeration, attack-path analysis and Windows protocol testing." },
];

/* ───────────────────────── Web ───────────────────────── */
tool({
  id: "burpsuite", name: "Burp Suite", category: "web", kind: "gui",
  description: "Industry-standard intercepting proxy for manual web application testing, with repeater, intruder and scanner (Professional) modules.",
  website: "https://portswigger.net/burp", docs: "https://portswigger.net/burp/documentation",
  os: ALL, tags: ["proxy", "web", "manual-testing"],
  detect: {
    binaries: ["BurpSuiteCommunity", "BurpSuitePro", "burpsuite"],
    paths: {
      windows: ["{LOCALAPPDATA}\\Programs\\BurpSuiteCommunity\\BurpSuiteCommunity.exe", "{ProgramFiles}\\BurpSuiteCommunity\\BurpSuiteCommunity.exe", "{LOCALAPPDATA}\\Programs\\BurpSuitePro\\BurpSuitePro.exe", "{ProgramFiles}\\BurpSuitePro\\BurpSuitePro.exe"],
      macos: ["/Applications/Burp Suite Community Edition.app", "/Applications/Burp Suite Professional.app"],
      linux: ["{HOME}/BurpSuiteCommunity/BurpSuiteCommunity", "{HOME}/BurpSuitePro/BurpSuitePro"],
    },
  },
  install: {
    windows: ["Download the Community Edition installer from https://portswigger.net/burp/releases", "Or: winget install --id PortSwigger.BurpSuite.Community -e"],
    macos: ["Download the macOS installer from https://portswigger.net/burp/releases", "Or: brew install --cask burp-suite"],
    linux: ["Download the Linux installer (.sh) from https://portswigger.net/burp/releases", "chmod +x burpsuite_community_linux_*.sh && ./burpsuite_community_linux_*.sh"],
  },
  managed: [winget("PortSwigger.BurpSuite.Community"), cask("burp-suite")],
  commands: [
    ex("Configure browser proxy", "Proxy listener: 127.0.0.1:8080", "Point your browser or tool at Burp's default proxy listener."),
    ex("Export CA certificate", "http://burpsuite/cert", "Open in a proxied browser to download Burp's CA certificate for HTTPS interception."),
  ],
});
tool({
  id: "zap", name: "OWASP ZAP", category: "web", kind: "gui",
  description: "Free, open-source intercepting proxy and automated web application scanner maintained by the ZAP project (formerly OWASP ZAP).",
  website: "https://www.zaproxy.org", docs: "https://www.zaproxy.org/docs/",
  os: ALL, tags: ["proxy", "scanner", "web", "open-source"],
  detect: {
    binaries: ["zaproxy", "zap", "zap.sh"],
    paths: {
      windows: ["{ProgramFiles}\\ZAP\\Zed Attack Proxy\\ZAP.exe", "{ProgramFiles(x86)}\\ZAP\\Zed Attack Proxy\\ZAP.exe"],
      macos: ["/Applications/ZAP.app", "/Applications/OWASP ZAP.app"],
      linux: ["/usr/share/zaproxy/zap.sh", "/opt/zaproxy/zap.sh"],
    },
  },
  install: {
    windows: ["Download the Windows installer from https://www.zaproxy.org/download/", "Or: winget install --id ZAP.ZAP -e"],
    macos: ["Download the macOS installer from https://www.zaproxy.org/download/", "Or: brew install --cask zap"],
    linux: ["sudo apt install zaproxy   # Kali / Debian-based", "Or download the cross-platform package from https://www.zaproxy.org/download/"],
  },
  managed: [winget("ZAP.ZAP"), cask("zap")],
  dependencies: [{ name: "Java (bundled on Windows/macOS installers)", binaries: ["java"], optional: true }],
  commands: [
    ex("Baseline scan (Docker)", "docker run -t zaproxy/zap-stable zap-baseline.py -t {url}", "Passive baseline scan of an authorized target URL."),
    ex("Headless daemon", "zap.sh -daemon -port 8090", "Run ZAP without UI for API-driven automation."),
  ],
});
tool({
  id: "sqlmap", name: "sqlmap", category: "web", builder: "sqlmap",
  description: "Automatic SQL injection detection and exploitation tool supporting a wide range of database engines and injection techniques.",
  website: "https://sqlmap.org", docs: "https://github.com/sqlmapproject/sqlmap/wiki/Usage",
  os: ALL, tags: ["sqli", "injection", "database"],
  detect: { binaries: ["sqlmap", "sqlmap.py"], versionArgs: ["--version"] },
  install: {
    windows: ["pipx install sqlmap", "Or: git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git"],
    macos: ["brew install sqlmap", "Or: pipx install sqlmap"],
    linux: ["sudo apt install sqlmap", "Or: pipx install sqlmap"],
  },
  managed: [brew("sqlmap"), pipx("sqlmap")],
  dependencies: [PY],
  commands: [
    ex("Test a URL parameter", "sqlmap -u \"{url}\" --batch", "Detect SQL injection in the URL's query parameters with default answers."),
    ex("Test a saved request", "sqlmap -r request.txt --batch --level 2", "Use a raw HTTP request captured from a proxy."),
    ex("Enumerate databases", "sqlmap -u \"{url}\" --batch --dbs", "List databases once an injection point is confirmed."),
  ],
  requiresScope: true,
});
tool({
  id: "nuclei", name: "Nuclei", category: "web", builder: "nuclei",
  description: "Fast, template-based vulnerability scanner from ProjectDiscovery with thousands of community-maintained YAML templates.",
  website: "https://github.com/projectdiscovery/nuclei", docs: "https://docs.projectdiscovery.io/tools/nuclei/overview",
  os: ALL, tags: ["scanner", "templates", "web", "projectdiscovery"],
  detect: { binaries: ["nuclei"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Or download a release binary from https://github.com/projectdiscovery/nuclei/releases"],
    macos: ["brew install nuclei"],
    linux: ["go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "Or: sudo apt install nuclei   # Kali"],
  },
  managed: [brew("nuclei"), go("github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Scan a single target", "nuclei -u {url}", "Run the default template set against one URL."),
    ex("Scan by severity", "nuclei -u {url} -severity high,critical", "Only run high and critical severity templates."),
    ex("Scan a target list", "nuclei -l targets.txt -o results.txt", "Scan every URL in a file and save results."),
  ],
  requiresScope: true,
});
tool({
  id: "ffuf", name: "ffuf", category: "web", builder: "ffuf",
  description: "Fast web fuzzer written in Go for content discovery, virtual host discovery and parameter fuzzing.",
  website: "https://github.com/ffuf/ffuf", docs: "https://github.com/ffuf/ffuf#usage",
  os: ALL, tags: ["fuzzing", "content-discovery", "web"],
  detect: { binaries: ["ffuf"], versionArgs: ["-V"] },
  install: {
    windows: ["go install github.com/ffuf/ffuf/v2@latest", "Or download a release binary from https://github.com/ffuf/ffuf/releases"],
    macos: ["brew install ffuf"],
    linux: ["sudo apt install ffuf", "Or: go install github.com/ffuf/ffuf/v2@latest"],
  },
  managed: [brew("ffuf"), go("github.com/ffuf/ffuf/v2@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Directory discovery", "ffuf -u {url}/FUZZ -w {wordlist}", "Fuzz paths using the FUZZ keyword."),
    ex("Filter by status", "ffuf -u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403", "Only show matching status codes."),
    ex("Virtual host discovery", "ffuf -u {url} -H \"Host: FUZZ.{domain}\" -w {wordlist} -fs 0", "Fuzz the Host header to discover virtual hosts."),
  ],
  requiresScope: true,
});
tool({
  id: "gobuster", name: "Gobuster", category: "web", builder: "gobuster",
  description: "Brute-forcing tool for URIs (directories and files), DNS subdomains, virtual hosts and cloud buckets.",
  website: "https://github.com/OJ/gobuster", docs: "https://github.com/OJ/gobuster#usage",
  os: ALL, tags: ["content-discovery", "dns", "web"],
  detect: { binaries: ["gobuster"], versionArgs: ["version"] },
  install: {
    windows: ["go install github.com/OJ/gobuster/v3@latest", "Or download a release from https://github.com/OJ/gobuster/releases"],
    macos: ["brew install gobuster"],
    linux: ["sudo apt install gobuster", "Or: go install github.com/OJ/gobuster/v3@latest"],
  },
  managed: [brew("gobuster"), go("github.com/OJ/gobuster/v3@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Directory mode", "gobuster dir -u {url} -w {wordlist}", "Enumerate directories and files."),
    ex("DNS mode", "gobuster dns -d {domain} -w {wordlist}", "Brute-force subdomains."),
    ex("Vhost mode", "gobuster vhost -u {url} -w {wordlist} --append-domain", "Discover virtual hosts."),
  ],
  requiresScope: true,
});
tool({
  id: "nikto", name: "Nikto", category: "web",
  description: "Open-source web server scanner that checks for dangerous files, outdated server software and common misconfigurations.",
  website: "https://github.com/sullo/nikto", docs: "https://github.com/sullo/nikto/wiki",
  os: ALL, tags: ["scanner", "web-server", "misconfiguration"],
  detect: { binaries: ["nikto", "nikto.pl"], versionArgs: ["-Version"] },
  install: {
    windows: ["Install Strawberry Perl, then: git clone https://github.com/sullo/nikto.git", "Run with: perl nikto/program/nikto.pl -h {url}"],
    macos: ["brew install nikto"],
    linux: ["sudo apt install nikto"],
  },
  managed: [brew("nikto")],
  dependencies: [PERL],
  commands: [
    ex("Scan a host", "nikto -h {url}", "Run the default checks against a web server."),
    ex("Save HTML report", "nikto -h {url} -o report.html -Format htm", "Write results to an HTML report."),
  ],
  requiresScope: true,
});
tool({
  id: "httpx", name: "httpx", category: "web", builder: "httpx",
  description: "Fast multi-purpose HTTP toolkit from ProjectDiscovery for probing live hosts, status codes, titles and technologies.",
  website: "https://github.com/projectdiscovery/httpx", docs: "https://docs.projectdiscovery.io/tools/httpx/overview",
  os: ALL, tags: ["http", "probing", "projectdiscovery"],
  detect: { binaries: ["httpx"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    macos: ["go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "Note: the Homebrew 'httpx' formula is a different (Python) tool."],
    linux: ["go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "Note: Debian's python3-httpx provides a different 'httpx' command."],
  },
  managed: [go("github.com/projectdiscovery/httpx/cmd/httpx@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Probe a host list", "httpx -l hosts.txt -sc -title -td", "Show status code, title and detected technologies."),
    ex("Probe one target", "httpx -u {url} -sc -cl -server", "Status code, content length and server header."),
  ],
  requiresScope: true,
});
tool({
  id: "dalfox", name: "Dalfox", category: "web",
  description: "Parameter analysis and XSS scanning tool focused on finding and verifying reflected and DOM-based cross-site scripting.",
  website: "https://github.com/hahwul/dalfox", docs: "https://dalfox.hahwul.com/docs/",
  os: ALL, tags: ["xss", "scanner", "web"],
  detect: { binaries: ["dalfox"], versionArgs: ["version"] },
  install: {
    windows: ["go install github.com/hahwul/dalfox/v2@latest"],
    macos: ["go install github.com/hahwul/dalfox/v2@latest"],
    linux: ["go install github.com/hahwul/dalfox/v2@latest", "Or: sudo snap install dalfox"],
  },
  managed: [go("github.com/hahwul/dalfox/v2@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Scan a URL", "dalfox url \"{url}\"", "Analyze parameters and test for XSS."),
    ex("Scan from file", "dalfox file urls.txt -o xss.txt", "Scan multiple URLs and save findings."),
  ],
  requiresScope: true,
});
tool({
  id: "feroxbuster", name: "feroxbuster", category: "web",
  description: "Fast, recursive content discovery tool written in Rust.",
  website: "https://github.com/epi052/feroxbuster", docs: "https://epi052.github.io/feroxbuster-docs/",
  os: ALL, tags: ["content-discovery", "recursive", "web"],
  detect: { binaries: ["feroxbuster"], versionArgs: ["--version"] },
  install: {
    windows: ["Download the Windows release zip from https://github.com/epi052/feroxbuster/releases", "Or: winget install epi052.feroxbuster (if available)"],
    macos: ["brew install feroxbuster"],
    linux: ["sudo apt install feroxbuster"],
  },
  managed: [brew("feroxbuster")],
  commands: [
    ex("Recursive scan", "feroxbuster -u {url} -w {wordlist}", "Discover content recursively."),
    ex("Limit depth", "feroxbuster -u {url} -w {wordlist} -d 2 -x php,txt", "Limit recursion depth and add extensions."),
  ],
  requiresScope: true,
});
tool({
  id: "wpscan", name: "WPScan", category: "web",
  description: "WordPress security scanner that enumerates versions, plugins, themes and users and checks them against the WPScan vulnerability database.",
  website: "https://wpscan.com", docs: "https://github.com/wpscanteam/wpscan/wiki/WPScan-User-Documentation",
  os: UNIX, tags: ["wordpress", "cms", "scanner"],
  detect: { binaries: ["wpscan"], versionArgs: ["--version"] },
  install: {
    macos: ["brew install wpscanteam/tap/wpscan", "Or: gem install wpscan"],
    linux: ["sudo apt install wpscan", "Or: gem install wpscan"],
  },
  dependencies: [RUBY],
  commands: [
    ex("Basic scan", "wpscan --url {url}", "Fingerprint WordPress core, theme and plugins."),
    ex("Enumerate plugins", "wpscan --url {url} -e vp,vt", "Enumerate vulnerable plugins and themes (API token recommended)."),
  ],
  requiresScope: true,
});
tool({
  id: "katana", name: "Katana", category: "web",
  description: "Next-generation crawling and spidering framework from ProjectDiscovery with headless and standard modes.",
  website: "https://github.com/projectdiscovery/katana", docs: "https://docs.projectdiscovery.io/tools/katana/overview",
  os: ALL, tags: ["crawler", "spider", "projectdiscovery"],
  detect: { binaries: ["katana"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["go install github.com/projectdiscovery/katana/cmd/katana@latest"],
    macos: ["go install github.com/projectdiscovery/katana/cmd/katana@latest"],
    linux: ["go install github.com/projectdiscovery/katana/cmd/katana@latest"],
  },
  managed: [go("github.com/projectdiscovery/katana/cmd/katana@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Crawl a site", "katana -u {url}", "Crawl and list discovered endpoints."),
    ex("Limit depth with JS parsing", "katana -u {url} -d 3 -jc", "Crawl three levels deep and parse JavaScript files."),
  ],
  requiresScope: true,
});

/* ───────────────────────── Network ───────────────────────── */
tool({
  id: "nmap", name: "Nmap", category: "network", builder: "nmap",
  description: "The standard network mapper for host discovery, port scanning, service and OS detection, with the Nmap Scripting Engine (NSE).",
  website: "https://nmap.org", docs: "https://nmap.org/book/man.html",
  os: ALL, tags: ["port-scanning", "discovery", "nse"],
  detect: {
    binaries: ["nmap"],
    paths: { windows: ["{ProgramFiles(x86)}\\Nmap\\nmap.exe", "{ProgramFiles}\\Nmap\\nmap.exe"] },
    versionArgs: ["--version"], versionRegex: "Nmap version (\\d+\\.\\d+(?:\\.\\d+)*)",
  },
  install: {
    windows: ["Download the installer from https://nmap.org/download.html (includes Npcap)", "Or: winget install --id Insecure.Nmap -e"],
    macos: ["brew install nmap", "Or use the official .dmg from https://nmap.org/download.html"],
    linux: ["sudo apt install nmap   # Debian/Ubuntu/Kali", "sudo dnf install nmap   # Fedora/RHEL"],
  },
  managed: [winget("Insecure.Nmap"), brew("nmap")],
  commands: [
    ex("Service/version scan", "nmap -sV -sC {target}", "Detect service versions and run default scripts."),
    ex("All TCP ports", "nmap -p- --min-rate 1000 {target}", "Scan all 65535 TCP ports."),
    ex("Ping sweep", "nmap -sn {target}", "Discover live hosts without port scanning."),
  ],
  requiresScope: true,
});
tool({
  id: "wireshark", name: "Wireshark", category: "network", kind: "gui",
  description: "The world's most widely used network protocol analyzer for live capture and deep inspection of hundreds of protocols.",
  website: "https://www.wireshark.org", docs: "https://www.wireshark.org/docs/",
  os: ALL, tags: ["packet-capture", "protocol-analysis", "pcap"],
  detect: {
    binaries: ["Wireshark", "wireshark"],
    paths: { windows: ["{ProgramFiles}\\Wireshark\\Wireshark.exe"], macos: ["/Applications/Wireshark.app"] },
  },
  install: {
    windows: ["Download the installer from https://www.wireshark.org/download.html (includes Npcap)", "Or: winget install --id WiresharkFoundation.Wireshark -e"],
    macos: ["brew install --cask wireshark", "Or download the .dmg from https://www.wireshark.org/download.html"],
    linux: ["sudo apt install wireshark", "sudo usermod -aG wireshark $USER   # capture without root"],
  },
  managed: [winget("WiresharkFoundation.Wireshark"), cask("wireshark")],
  commands: [
    ex("Display filter: HTTP", "http.request", "Show only HTTP requests."),
    ex("Display filter: host", "ip.addr == {target}", "Show traffic to/from one host."),
  ],
});
tool({
  id: "tshark", name: "TShark", category: "network",
  description: "Terminal-based version of Wireshark for capturing and analyzing packets from the command line.",
  website: "https://www.wireshark.org", docs: "https://www.wireshark.org/docs/man-pages/tshark.html",
  os: ALL, tags: ["packet-capture", "cli", "pcap"],
  detect: {
    binaries: ["tshark"],
    paths: { windows: ["{ProgramFiles}\\Wireshark\\tshark.exe"], macos: ["/Applications/Wireshark.app/Contents/MacOS/tshark"] },
    versionArgs: ["--version"], versionRegex: "TShark \\(Wireshark\\) (\\d+\\.\\d+(?:\\.\\d+)*)",
  },
  install: {
    windows: ["Installed together with Wireshark (select TShark in the installer)."],
    macos: ["brew install --cask wireshark   # includes tshark", "Or: brew install wireshark"],
    linux: ["sudo apt install tshark"],
  },
  commands: [
    ex("List interfaces", "tshark -D", "List capture interfaces."),
    ex("Read a capture", "tshark -r capture.pcap -Y http.request", "Apply a display filter to a pcap file."),
  ],
});
tool({
  id: "netcat", name: "Netcat / Ncat", category: "network",
  description: "Swiss-army knife for reading and writing raw TCP/UDP connections; Ncat is the modern Nmap-project implementation.",
  website: "https://nmap.org/ncat/", docs: "https://nmap.org/ncat/guide/",
  os: ALL, tags: ["tcp", "udp", "connectivity"],
  detect: {
    binaries: ["ncat", "nc"],
    paths: { windows: ["{ProgramFiles(x86)}\\Nmap\\ncat.exe", "{ProgramFiles}\\Nmap\\ncat.exe"] },
  },
  install: {
    windows: ["Installed with Nmap (Ncat component)."],
    macos: ["nc ships with macOS; for Ncat: brew install nmap"],
    linux: ["sudo apt install ncat   # or netcat-openbsd"],
  },
  commands: [
    ex("Test a TCP port", "ncat -zv {target} 443", "Check whether a port accepts connections."),
    ex("Grab a banner", "ncat {target} 22", "Connect and read the service banner."),
  ],
  requiresScope: true,
});
tool({
  id: "masscan", name: "Masscan", category: "network",
  description: "Internet-scale asynchronous TCP port scanner capable of very high packet rates.",
  website: "https://github.com/robertdavidgraham/masscan", docs: "https://github.com/robertdavidgraham/masscan#usage",
  os: ALL, tags: ["port-scanning", "high-speed"],
  detect: { binaries: ["masscan"], versionArgs: ["--version"], versionRegex: "Masscan version (\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["Build from source with Visual Studio: https://github.com/robertdavidgraham/masscan"],
    macos: ["brew install masscan"],
    linux: ["sudo apt install masscan"],
  },
  managed: [brew("masscan")],
  commands: [
    ex("Scan common ports", "masscan {target} -p80,443,8080 --rate 1000", "Scan selected ports at a controlled rate."),
    ex("All ports", "masscan {target} -p0-65535 --rate 500", "Scan all ports (keep rates low on production networks)."),
  ],
  requiresScope: true,
});
tool({
  id: "tcpdump", name: "tcpdump", category: "network",
  description: "Classic command-line packet analyzer for capturing and filtering network traffic using BPF expressions.",
  website: "https://www.tcpdump.org", docs: "https://www.tcpdump.org/manpages/tcpdump.1.html",
  os: UNIX, tags: ["packet-capture", "bpf", "cli"],
  detect: { binaries: ["tcpdump"], versionArgs: ["--version"], versionRegex: "tcpdump version (\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    macos: ["Preinstalled on macOS."],
    linux: ["sudo apt install tcpdump"],
  },
  commands: [
    ex("Capture on interface", "sudo tcpdump -i eth0 -w capture.pcap", "Write packets to a pcap file."),
    ex("Filter by host and port", "sudo tcpdump -i any host {target} and port 443", "Capture traffic for one host and port."),
  ],
});
tool({
  id: "rustscan", name: "RustScan", category: "network",
  description: "Fast port scanner that finds open ports quickly and hands them to Nmap for detailed scanning.",
  website: "https://github.com/bee-san/RustScan", docs: "https://github.com/bee-san/RustScan/wiki",
  os: ALL, tags: ["port-scanning", "fast", "nmap"],
  detect: { binaries: ["rustscan"], versionArgs: ["--version"] },
  install: {
    windows: ["cargo install rustscan", "Or download a release from https://github.com/bee-san/RustScan/releases"],
    macos: ["brew install rustscan"],
    linux: ["cargo install rustscan", "Or install the .deb from the releases page"],
  },
  managed: [brew("rustscan")],
  dependencies: [{ name: "Nmap (for follow-up scans)", binaries: ["nmap"], optional: true }],
  commands: [
    ex("Scan and pass to Nmap", "rustscan -a {target} -- -sV", "Find open ports, then run Nmap service detection."),
    ex("Custom batch size", "rustscan -a {target} -b 1000 --ulimit 5000", "Tune concurrency."),
  ],
  requiresScope: true,
});
tool({
  id: "naabu", name: "Naabu", category: "network",
  description: "Fast port scanner from ProjectDiscovery written in Go, designed for reliability and pipeline integration.",
  website: "https://github.com/projectdiscovery/naabu", docs: "https://docs.projectdiscovery.io/tools/naabu/overview",
  os: ALL, tags: ["port-scanning", "projectdiscovery"],
  detect: { binaries: ["naabu"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["Download a release from https://github.com/projectdiscovery/naabu/releases (requires Npcap)"],
    macos: ["brew install libpcap && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"],
    linux: ["sudo apt install libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"],
  },
  dependencies: [{ name: "libpcap / Npcap", binaries: [], optional: true }],
  commands: [
    ex("Top ports", "naabu -host {target} -top-ports 100", "Scan the 100 most common ports."),
    ex("Pipe to httpx", "naabu -host {target} -silent | httpx -silent", "Find open ports and probe for HTTP services."),
  ],
  requiresScope: true,
});

/* ───────────────────────── OSINT ───────────────────────── */
tool({
  id: "theharvester", name: "theHarvester", category: "osint",
  description: "Gathers emails, names, subdomains, IPs and URLs from public sources such as search engines and certificate logs.",
  website: "https://github.com/laramies/theHarvester", docs: "https://github.com/laramies/theHarvester/wiki",
  os: UNIX, tags: ["emails", "subdomains", "osint"],
  detect: { binaries: ["theHarvester", "theharvester"] },
  install: {
    macos: ["git clone https://github.com/laramies/theHarvester && cd theHarvester", "Follow the installation steps in the project wiki (uses uv / Python 3.12+)."],
    linux: ["sudo apt install theharvester   # Kali", "Or follow https://github.com/laramies/theHarvester/wiki/Installation"],
  },
  dependencies: [PY],
  commands: [
    ex("Search public sources", "theHarvester -d {domain} -b crtsh,duckduckgo", "Collect hosts and emails for a domain."),
    ex("Limit results", "theHarvester -d {domain} -b all -l 200", "Query all supported sources with a result limit."),
  ],
  requiresScope: true,
});
tool({
  id: "sherlock", name: "Sherlock", category: "osint",
  description: "Hunts down social media accounts by username across hundreds of websites.",
  website: "https://github.com/sherlock-project/sherlock", docs: "https://sherlockproject.xyz",
  os: ALL, tags: ["username", "social-media", "osint"],
  detect: { binaries: ["sherlock"], versionArgs: ["--version"] },
  install: {
    windows: ["pipx install sherlock-project"],
    macos: ["pipx install sherlock-project", "Or: brew install sherlock"],
    linux: ["pipx install sherlock-project", "Or: sudo apt install sherlock"],
  },
  managed: [pipx("sherlock-project")],
  dependencies: [PY],
  commands: [
    ex("Search a username", "sherlock {username}", "Check which sites have an account with this username."),
    ex("Save to CSV", "sherlock {username} --csv", "Export results as CSV."),
  ],
});
tool({
  id: "spiderfoot", name: "SpiderFoot", category: "osint",
  description: "OSINT automation framework with 200+ modules and a web UI for correlating data about IPs, domains, emails and names.",
  website: "https://github.com/smicallef/spiderfoot", docs: "https://github.com/smicallef/spiderfoot#readme",
  os: ALL, tags: ["automation", "osint", "web-ui"],
  detect: { binaries: ["spiderfoot", "sf.py"] },
  install: {
    windows: ["git clone https://github.com/smicallef/spiderfoot.git && cd spiderfoot", "pip install -r requirements.txt", "python sf.py -l 127.0.0.1:5001"],
    macos: ["git clone https://github.com/smicallef/spiderfoot.git && cd spiderfoot", "pip3 install -r requirements.txt"],
    linux: ["sudo apt install spiderfoot   # Kali", "Or clone the repository and install requirements"],
  },
  dependencies: [PY],
  commands: [
    ex("Start web UI", "spiderfoot -l 127.0.0.1:5001", "Launch the local web interface."),
    ex("CLI scan", "spiderfoot -s {domain} -u passive", "Run a passive scan from the command line."),
  ],
});
tool({
  id: "shodan", name: "Shodan", category: "osint", kind: "web",
  description: "Search engine for Internet-connected devices, exposing banners, open services and known vulnerabilities.",
  website: "https://www.shodan.io", docs: "https://help.shodan.io",
  os: ALL, tags: ["search-engine", "iot", "exposure"],
  install: {
    windows: ["Web service — no installation required. Optional CLI: pipx install shodan"],
    macos: ["Web service — no installation required. Optional CLI: pipx install shodan"],
    linux: ["Web service — no installation required. Optional CLI: pipx install shodan"],
  },
  commands: [
    ex("Search your org's exposure", "org:\"{organization}\"", "Shodan search filter for an organization."),
    ex("Hostname filter", "hostname:{domain}", "Find services whose hostname matches your domain."),
  ],
});
tool({
  id: "censys", name: "Censys Search", category: "osint", kind: "web",
  description: "Internet-wide scan data and certificate search for discovering hosts, services and certificates.",
  website: "https://search.censys.io", docs: "https://docs.censys.com",
  os: ALL, tags: ["search-engine", "certificates", "exposure"],
  install: {
    windows: ["Web service — no installation required."],
    macos: ["Web service — no installation required."],
    linux: ["Web service — no installation required."],
  },
  commands: [
    ex("Hosts by name", "services.tls.certificates.leaf_data.subject.common_name: \"{domain}\"", "Find hosts presenting certificates for your domain."),
  ],
});
tool({
  id: "maltego", name: "Maltego", category: "osint", kind: "gui",
  description: "Graphical link-analysis platform for visualizing relationships between people, organizations, domains and infrastructure.",
  website: "https://www.maltego.com", docs: "https://docs.maltego.com",
  os: ALL, tags: ["link-analysis", "graph", "osint"],
  detect: {
    binaries: ["maltego"],
    paths: { windows: ["{ProgramFiles}\\Maltego\\bin\\maltego.exe", "{ProgramFiles(x86)}\\Maltego\\bin\\maltego.exe"], macos: ["/Applications/Maltego.app"] },
  },
  install: {
    windows: ["Download from https://www.maltego.com/downloads/"],
    macos: ["Download from https://www.maltego.com/downloads/"],
    linux: ["sudo apt install maltego   # Kali", "Or download the .deb/.rpm from https://www.maltego.com/downloads/"],
  },
  commands: [
    ex("Start a graph", "New Graph → add a Domain entity → run 'To DNS Name' transforms", "Typical starting workflow for domain mapping."),
  ],
});

/* ───────────────────────── Recon ───────────────────────── */
tool({
  id: "amass", name: "OWASP Amass", category: "recon",
  description: "In-depth attack surface mapping and asset discovery using passive sources, DNS enumeration and graph storage.",
  website: "https://github.com/owasp-amass/amass", docs: "https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md",
  os: ALL, tags: ["subdomains", "attack-surface", "dns"],
  detect: { binaries: ["amass"], versionArgs: ["-version"] },
  install: {
    windows: ["Download a release zip from https://github.com/owasp-amass/amass/releases"],
    macos: ["brew install amass"],
    linux: ["sudo apt install amass", "Or: sudo snap install amass"],
  },
  managed: [brew("amass")],
  commands: [
    ex("Passive enumeration", "amass enum -passive -d {domain}", "Enumerate subdomains from passive sources only."),
    ex("Active enumeration", "amass enum -active -d {domain} -o amass.txt", "Include DNS resolution and zone-transfer attempts."),
  ],
  requiresScope: true,
});
tool({
  id: "subfinder", name: "Subfinder", category: "recon", builder: "subfinder",
  description: "Passive subdomain discovery tool from ProjectDiscovery that queries many online sources.",
  website: "https://github.com/projectdiscovery/subfinder", docs: "https://docs.projectdiscovery.io/tools/subfinder/overview",
  os: ALL, tags: ["subdomains", "passive", "projectdiscovery"],
  detect: { binaries: ["subfinder"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    macos: ["brew install subfinder"],
    linux: ["go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "Or: sudo apt install subfinder   # Kali"],
  },
  managed: [brew("subfinder"), go("github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Enumerate subdomains", "subfinder -d {domain}", "List subdomains from passive sources."),
    ex("All sources, silent", "subfinder -d {domain} -all -silent -o subs.txt", "Use every source and save results."),
  ],
  requiresScope: true,
});
tool({
  id: "dnsx", name: "dnsx", category: "recon",
  description: "Fast multi-purpose DNS toolkit for resolving, brute-forcing and querying many record types at scale.",
  website: "https://github.com/projectdiscovery/dnsx", docs: "https://docs.projectdiscovery.io/tools/dnsx/overview",
  os: ALL, tags: ["dns", "resolution", "projectdiscovery"],
  detect: { binaries: ["dnsx"], versionArgs: ["-version", "-duc"], versionRegex: "[Vv]ersion:?\\s*v?(\\d+\\.\\d+(?:\\.\\d+)*)" },
  install: {
    windows: ["go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    macos: ["go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    linux: ["go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
  },
  managed: [go("github.com/projectdiscovery/dnsx/cmd/dnsx@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Resolve a list", "dnsx -l subs.txt -a -resp", "Resolve A records and print responses."),
    ex("Query record types", "echo {domain} | dnsx -mx -txt -resp", "Show MX and TXT records."),
  ],
  requiresScope: true,
});
tool({
  id: "whatweb", name: "WhatWeb", category: "recon",
  description: "Web technology fingerprinting tool with 1,800+ plugins that identifies CMSs, frameworks, servers and analytics.",
  website: "https://github.com/urbanadventurer/WhatWeb", docs: "https://github.com/urbanadventurer/WhatWeb/wiki",
  os: UNIX, tags: ["fingerprinting", "technology", "web"],
  detect: { binaries: ["whatweb"], versionArgs: ["--version"] },
  install: {
    macos: ["brew install whatweb"],
    linux: ["sudo apt install whatweb"],
  },
  dependencies: [RUBY],
  commands: [
    ex("Fingerprint a site", "whatweb {url}", "Identify technologies used by a site."),
    ex("Verbose output", "whatweb -v -a 1 {url}", "Detailed, stealthy (aggression level 1) output."),
  ],
  requiresScope: true,
});
tool({
  id: "assetfinder", name: "assetfinder", category: "recon",
  description: "Lightweight tool that finds domains and subdomains related to a given domain from passive sources.",
  website: "https://github.com/tomnomnom/assetfinder", docs: "https://github.com/tomnomnom/assetfinder#readme",
  os: ALL, tags: ["subdomains", "passive"],
  detect: { binaries: ["assetfinder"] },
  install: {
    windows: ["go install github.com/tomnomnom/assetfinder@latest"],
    macos: ["go install github.com/tomnomnom/assetfinder@latest"],
    linux: ["go install github.com/tomnomnom/assetfinder@latest", "Or: sudo apt install assetfinder   # Kali"],
  },
  managed: [go("github.com/tomnomnom/assetfinder@latest")],
  dependencies: [GOLANG],
  commands: [
    ex("Subdomains only", "assetfinder --subs-only {domain}", "List subdomains of the target domain."),
  ],
  requiresScope: true,
});

/* ───────────────────────── Vulnerability assessment ───────────────────────── */
tool({
  id: "searchsploit", name: "SearchSploit", category: "vuln",
  description: "Command-line search for the offline copy of Exploit Database, useful for matching versions to public exploits and advisories.",
  website: "https://www.exploit-db.com/searchsploit", docs: "https://www.exploit-db.com/searchsploit",
  os: UNIX, tags: ["exploit-db", "offline", "research"],
  detect: { binaries: ["searchsploit"] },
  install: {
    macos: ["brew install exploitdb"],
    linux: ["sudo apt install exploitdb   # Kali", "Or: git clone https://gitlab.com/exploit-database/exploitdb.git"],
  },
  commands: [
    ex("Search by product", "searchsploit apache 2.4", "Find entries for a product and version."),
    ex("Show path / copy", "searchsploit -m {edb_id}", "Copy an entry to the current directory for review."),
  ],
});
tool({
  id: "openvas", name: "Greenbone OpenVAS", category: "vuln",
  description: "Full-featured open-source vulnerability scanner (Greenbone Community Edition) with a large feed of network vulnerability tests.",
  website: "https://www.openvas.org", docs: "https://greenbone.github.io/docs/latest/",
  os: LINUX, tags: ["scanner", "network", "vulnerability"],
  detect: { binaries: ["gvm-start", "gvmd", "openvas"] },
  install: {
    linux: ["sudo apt install gvm   # Kali", "sudo gvm-setup", "sudo gvm-check-setup", "Or use the official container setup: https://greenbone.github.io/docs/latest/22.4/container/"],
  },
  commands: [
    ex("Start services", "sudo gvm-start", "Start the Greenbone services and web UI (https://127.0.0.1:9392)."),
    ex("Verify setup", "sudo gvm-check-setup", "Check the installation and feed status."),
  ],
  requiresScope: true,
});

/* ───────────────────────── Password auditing ───────────────────────── */
tool({
  id: "hashcat", name: "Hashcat", category: "password",
  description: "GPU-accelerated password recovery tool supporting hundreds of hash types; used to audit password strength of hashes you are authorized to test.",
  website: "https://hashcat.net/hashcat/", docs: "https://hashcat.net/wiki/",
  os: ALL, tags: ["hash-cracking", "gpu", "password"],
  detect: { binaries: ["hashcat"], versionArgs: ["--version"] },
  install: {
    windows: ["Download the binaries from https://hashcat.net/hashcat/ and extract them (7-Zip)", "Install current GPU drivers (CUDA/OpenCL)"],
    macos: ["brew install hashcat"],
    linux: ["sudo apt install hashcat"],
  },
  managed: [brew("hashcat")],
  commands: [
    ex("Show example hashes", "hashcat --example-hashes", "List supported hash modes with sample hashes."),
    ex("Wordlist audit", "hashcat -m {mode} -a 0 {hashfile} {wordlist}", "Audit hashes against a wordlist (straight mode)."),
    ex("Show results", "hashcat -m {mode} {hashfile} --show", "Display hashes already recovered in the potfile."),
  ],
});
tool({
  id: "john", name: "John the Ripper", category: "password",
  description: "Open-source password security auditing tool (jumbo edition) with broad hash-format support and companion *2john extractors.",
  website: "https://www.openwall.com/john/", docs: "https://www.openwall.com/john/doc/",
  os: ALL, tags: ["hash-cracking", "password", "audit"],
  detect: { binaries: ["john"] },
  install: {
    windows: ["Download the jumbo Windows build from https://www.openwall.com/john/ and add the run folder to PATH"],
    macos: ["brew install john-jumbo"],
    linux: ["sudo apt install john"],
  },
  managed: [brew("john-jumbo")],
  commands: [
    ex("Wordlist audit", "john --wordlist={wordlist} {hashfile}", "Audit hashes using a wordlist."),
    ex("Show recovered", "john --show {hashfile}", "Show passwords recovered so far."),
    ex("List formats", "john --list=formats", "List supported hash formats."),
  ],
});
tool({
  id: "hydra", name: "THC Hydra", category: "password",
  description: "Network login auditing tool supporting many protocols; used to verify credential policies on systems you are authorized to test.",
  website: "https://github.com/vanhauser-thc/thc-hydra", docs: "https://github.com/vanhauser-thc/thc-hydra#readme",
  os: UNIX, tags: ["login-audit", "network", "password"],
  detect: { binaries: ["hydra"] },
  install: {
    macos: ["brew install hydra"],
    linux: ["sudo apt install hydra"],
  },
  managed: [brew("hydra")],
  commands: [
    ex("Module help", "hydra -U {service}", "Show options for a protocol module."),
    ex("Credential policy check", "hydra -L {userlist} -P {wordlist} -t 4 {target} {service}", "Check accounts against a password list at a low task count."),
  ],
  requiresScope: true,
});
tool({
  id: "cewl", name: "CeWL", category: "password",
  description: "Custom wordlist generator that spiders a website and collects words, useful for organization-specific password audits.",
  website: "https://github.com/digininja/CeWL", docs: "https://github.com/digininja/CeWL#readme",
  os: UNIX, tags: ["wordlist", "spider"],
  detect: { binaries: ["cewl"] },
  install: { macos: ["gem install cewl (see README for dependencies)"], linux: ["sudo apt install cewl"] },
  dependencies: [RUBY],
  commands: [
    ex("Generate wordlist", "cewl -d 2 -m 5 -w {output} {url}", "Spider to depth 2 and keep words of 5+ characters."),
  ],
  requiresScope: true,
});

/* ───────────────────────── Forensics ───────────────────────── */
tool({
  id: "autopsy", name: "Autopsy", category: "forensics", kind: "gui",
  description: "Graphical digital forensics platform built on The Sleuth Kit for disk image analysis, timelines and artifact extraction.",
  website: "https://www.autopsy.com/", docs: "https://sleuthkit.org/autopsy/docs/user-docs/latest/",
  os: ALL, tags: ["disk-forensics", "timeline", "gui"],
  detect: { binaries: ["autopsy", "autopsy64"], paths: { macos: ["/Applications/Autopsy.app"] } },
  install: {
    windows: ["Download the MSI installer from https://www.autopsy.com/download/"],
    macos: ["Follow the macOS instructions at https://github.com/sleuthkit/autopsy/blob/develop/Running_Linux_OSX.md"],
    linux: ["Follow https://github.com/sleuthkit/autopsy/blob/develop/Running_Linux_OSX.md (requires Java and The Sleuth Kit)"],
  },
  commands: [ex("Launch", "autopsy", "Start the Autopsy GUI and create a case.")],
});
tool({
  id: "volatility3", name: "Volatility 3", category: "forensics",
  description: "Memory forensics framework for extracting processes, network connections and artifacts from RAM captures.",
  website: "https://volatilityfoundation.org/", docs: "https://volatility3.readthedocs.io/",
  os: ALL, tags: ["memory-forensics", "dfir"],
  detect: { binaries: ["vol", "vol.py", "volatility3"] },
  install: {
    windows: ["pipx install volatility3"],
    macos: ["pipx install volatility3"],
    linux: ["pipx install volatility3"],
  },
  managed: [pipx("volatility3")],
  dependencies: [PY],
  commands: [
    ex("OS information", "vol -f {memdump} windows.info", "Identify the Windows build of a memory image."),
    ex("Process list", "vol -f {memdump} windows.pslist", "List processes in the image."),
    ex("Linux processes", "vol -f {memdump} linux.pslist", "List processes from a Linux memory image."),
  ],
});
tool({
  id: "binwalk", name: "Binwalk", category: "forensics",
  description: "Firmware analysis tool for identifying and extracting embedded files and file systems from binary images.",
  website: "https://github.com/ReFirmLabs/binwalk", docs: "https://github.com/ReFirmLabs/binwalk/wiki",
  os: UNIX, tags: ["firmware", "carving"],
  detect: { binaries: ["binwalk"] },
  install: { macos: ["brew install binwalk"], linux: ["sudo apt install binwalk"] },
  managed: [brew("binwalk")],
  commands: [
    ex("Signature scan", "binwalk {file}", "Identify embedded file signatures."),
    ex("Extract", "binwalk -e {file}", "Extract known embedded content."),
    ex("Entropy", "binwalk -E {file}", "Entropy analysis to spot compressed or encrypted regions."),
  ],
});
tool({
  id: "exiftool", name: "ExifTool", category: "forensics",
  description: "Reads, writes and edits metadata in a wide range of image, audio, video and document formats.",
  website: "https://exiftool.org/", docs: "https://exiftool.org/exiftool_pod.html",
  os: ALL, tags: ["metadata", "osint", "files"],
  detect: { binaries: ["exiftool"], versionArgs: ["-ver"] },
  install: {
    windows: ["winget install OliverBetz.ExifTool", "Or download from https://exiftool.org/"],
    macos: ["brew install exiftool"],
    linux: ["sudo apt install libimage-exiftool-perl"],
  },
  managed: [winget("OliverBetz.ExifTool"), brew("exiftool")],
  commands: [
    ex("Read metadata", "exiftool {file}", "Show all metadata."),
    ex("GPS only", "exiftool -gps:all {file}", "Show GPS tags."),
    ex("Strip metadata (copy)", "exiftool -all= -o {output} {file}", "Write a metadata-free copy."),
  ],
});
tool({
  id: "sleuthkit", name: "The Sleuth Kit", category: "forensics",
  description: "Command-line library and tools for file system forensic analysis of disk images.",
  website: "https://www.sleuthkit.org/sleuthkit/", docs: "https://wiki.sleuthkit.org/",
  os: ALL, tags: ["disk-forensics", "filesystem"],
  detect: { binaries: ["fls", "mmls"], versionArgs: ["-V"] },
  install: {
    windows: ["Download the Windows binaries from https://www.sleuthkit.org/sleuthkit/download.php"],
    macos: ["brew install sleuthkit"],
    linux: ["sudo apt install sleuthkit"],
  },
  managed: [brew("sleuthkit")],
  commands: [
    ex("Partition layout", "mmls {image}", "Display the partition table."),
    ex("List files", "fls -r -o {offset} {image}", "Recursively list files in a partition."),
  ],
});

/* ───────────────────────── Malware analysis ───────────────────────── */
tool({
  id: "yara", name: "YARA", category: "malware",
  description: "Pattern-matching engine for identifying and classifying malware samples with textual or binary rules.",
  website: "https://virustotal.github.io/yara/", docs: "https://yara.readthedocs.io/",
  os: ALL, tags: ["signatures", "detection"],
  detect: { binaries: ["yara", "yara64"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a release from https://github.com/VirusTotal/yara/releases"],
    macos: ["brew install yara"],
    linux: ["sudo apt install yara"],
  },
  managed: [brew("yara")],
  commands: [
    ex("Scan a file", "yara {rules} {file}", "Match rules against a file."),
    ex("Recursive scan", "yara -r {rules} {directory}", "Scan a directory recursively."),
  ],
});
tool({
  id: "capa", name: "capa", category: "malware",
  description: "Mandiant tool that identifies capabilities in executables (persistence, network communication, etc.) mapped to ATT&CK.",
  website: "https://github.com/mandiant/capa", docs: "https://github.com/mandiant/capa#readme",
  os: ALL, tags: ["static-analysis", "attack"],
  detect: { binaries: ["capa"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a standalone release from https://github.com/mandiant/capa/releases"],
    macos: ["Download a standalone release from https://github.com/mandiant/capa/releases"],
    linux: ["Download a standalone release from https://github.com/mandiant/capa/releases"],
  },
  commands: [
    ex("Analyze", "capa {file}", "Summarize capabilities of a sample."),
    ex("Verbose", "capa -vv {file}", "Show matched rule details."),
  ],
});
tool({
  id: "floss", name: "FLOSS", category: "malware",
  description: "FLARE Obfuscated String Solver: extracts static, stack and obfuscated strings from binaries.",
  website: "https://github.com/mandiant/flare-floss", docs: "https://github.com/mandiant/flare-floss#readme",
  os: ALL, tags: ["strings", "static-analysis"],
  detect: { binaries: ["floss"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a standalone release from https://github.com/mandiant/flare-floss/releases"],
    macos: ["Download a standalone release from https://github.com/mandiant/flare-floss/releases"],
    linux: ["Download a standalone release from https://github.com/mandiant/flare-floss/releases"],
  },
  commands: [ex("Extract strings", "floss {file}", "Extract all string types.")],
});
tool({
  id: "clamav", name: "ClamAV", category: "malware",
  description: "Open-source antivirus engine for detecting trojans, viruses and other malicious threats.",
  website: "https://www.clamav.net/", docs: "https://docs.clamav.net/",
  os: ALL, tags: ["antivirus", "scanning"],
  detect: { binaries: ["clamscan"], versionArgs: ["--version"] },
  install: {
    windows: ["Download the installer from https://www.clamav.net/downloads"],
    macos: ["brew install clamav"],
    linux: ["sudo apt install clamav"],
  },
  managed: [brew("clamav")],
  commands: [
    ex("Update signatures", "freshclam", "Download the latest signature database."),
    ex("Scan directory", "clamscan -r -i {directory}", "Recursively scan and print infected files only."),
  ],
});

/* ───────────────────────── Wireless ───────────────────────── */
tool({
  id: "aircrack-ng", name: "Aircrack-ng", category: "wireless",
  description: "Suite for assessing Wi-Fi network security: monitoring, capture analysis and key strength testing.",
  website: "https://www.aircrack-ng.org/", docs: "https://www.aircrack-ng.org/doku.php?id=Main",
  os: UNIX, tags: ["wifi", "802.11"],
  detect: { binaries: ["aircrack-ng"] },
  install: { macos: ["brew install aircrack-ng"], linux: ["sudo apt install aircrack-ng"] },
  managed: [brew("aircrack-ng")],
  commands: [
    ex("List interfaces", "sudo airmon-ng", "Show wireless interfaces and drivers."),
    ex("Analyze capture", "aircrack-ng {capture}", "Inspect a capture file for handshakes."),
  ],
});
tool({
  id: "kismet", name: "Kismet", category: "wireless",
  description: "Wireless network and device detector, sniffer and wardriving tool with a web UI.",
  website: "https://www.kismetwireless.net/", docs: "https://www.kismetwireless.net/docs/",
  os: UNIX, tags: ["wifi", "bluetooth", "monitoring"],
  detect: { binaries: ["kismet"] },
  install: { macos: ["See https://www.kismetwireless.net/packages/"], linux: ["sudo apt install kismet"] },
  commands: [ex("Start", "kismet", "Start Kismet and open the web UI at http://localhost:2501.")],
});
tool({
  id: "bettercap", name: "bettercap", category: "wireless",
  description: "Network monitoring and assessment framework for Wi-Fi, BLE and Ethernet reconnaissance in authorized labs.",
  website: "https://www.bettercap.org/", docs: "https://www.bettercap.org/docs/",
  os: ALL, tags: ["wifi", "ble", "network"],
  detect: { binaries: ["bettercap"], versionArgs: ["-version"] },
  install: {
    windows: ["Download a release from https://github.com/bettercap/bettercap/releases (requires Npcap)"],
    macos: ["brew install bettercap"],
    linux: ["sudo apt install bettercap"],
  },
  managed: [brew("bettercap")],
  commands: [ex("Interactive session", "sudo bettercap -iface {interface}", "Start an interactive session on an interface.")],
  requiresScope: true,
});

/* ───────────────────────── Cloud ───────────────────────── */
tool({
  id: "prowler", name: "Prowler", category: "cloud",
  description: "Cloud security posture assessment for AWS, Azure, GCP and Kubernetes against CIS, NIST and other frameworks.",
  website: "https://prowler.com/", docs: "https://docs.prowler.com/",
  os: ALL, tags: ["aws", "azure", "gcp", "compliance"],
  detect: { binaries: ["prowler"], versionArgs: ["--version"] },
  install: { windows: ["pipx install prowler"], macos: ["brew install prowler", "Or: pipx install prowler"], linux: ["pipx install prowler"] },
  managed: [pipx("prowler")],
  dependencies: [PY],
  commands: [
    ex("AWS assessment", "prowler aws", "Run all AWS checks with the current credentials."),
    ex("Compliance framework", "prowler aws --compliance cis_2.0_aws", "Evaluate against a compliance framework."),
  ],
});
tool({
  id: "scoutsuite", name: "ScoutSuite", category: "cloud",
  description: "Multi-cloud security auditing tool that gathers configuration data and highlights risk areas in an HTML report.",
  website: "https://github.com/nccgroup/ScoutSuite", docs: "https://github.com/nccgroup/ScoutSuite/wiki",
  os: ALL, tags: ["aws", "azure", "gcp", "audit"],
  detect: { binaries: ["scout"] },
  install: { windows: ["pipx install scoutsuite"], macos: ["pipx install scoutsuite"], linux: ["pipx install scoutsuite"] },
  managed: [pipx("scoutsuite")],
  dependencies: [PY],
  commands: [ex("AWS audit", "scout aws", "Audit the AWS account for the current profile.")],
});
tool({
  id: "trivy", name: "Trivy", category: "cloud",
  description: "Scanner for vulnerabilities, misconfigurations, secrets and SBOMs in containers, file systems, repos and Kubernetes.",
  website: "https://trivy.dev/", docs: "https://trivy.dev/latest/docs/",
  os: ALL, tags: ["containers", "sbom", "iac"],
  detect: { binaries: ["trivy"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a release from https://github.com/aquasecurity/trivy/releases"],
    macos: ["brew install trivy"],
    linux: ["See https://trivy.dev/latest/getting-started/installation/"],
  },
  managed: [brew("trivy")],
  commands: [
    ex("Scan image", "trivy image {image}", "Scan a container image."),
    ex("Scan project", "trivy fs {directory}", "Scan a local directory for vulnerable dependencies."),
    ex("IaC misconfigurations", "trivy config {directory}", "Scan Terraform and Kubernetes files."),
  ],
});

/* ───────────────────────── Reverse engineering ───────────────────────── */
tool({
  id: "ghidra", name: "Ghidra", category: "reversing", kind: "gui",
  description: "NSA's software reverse engineering suite with disassembly, decompilation, scripting and collaborative analysis.",
  website: "https://ghidra-sre.org/", docs: "https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md",
  os: ALL, tags: ["decompiler", "disassembler"],
  detect: { binaries: ["ghidraRun", "ghidra"] },
  install: {
    windows: ["Download from https://github.com/NationalSecurityAgency/ghidra/releases, extract and add the folder to PATH", "Requires JDK 21"],
    macos: ["brew install --cask ghidra", "Requires JDK 21"],
    linux: ["Download from https://github.com/NationalSecurityAgency/ghidra/releases and extract", "Requires JDK 21"],
  },
  managed: [cask("ghidra")],
  dependencies: [JAVA],
  commands: [ex("Launch", "ghidraRun", "Start Ghidra.")],
});
tool({
  id: "radare2", name: "radare2", category: "reversing",
  description: "Portable UNIX-like reverse engineering framework and command-line toolset.",
  website: "https://rada.re/n/", docs: "https://book.rada.re/",
  os: ALL, tags: ["disassembler", "debugger"],
  detect: { binaries: ["radare2", "r2"], versionArgs: ["-v"] },
  install: {
    windows: ["Download a release from https://github.com/radareorg/radare2/releases"],
    macos: ["brew install radare2"],
    linux: ["See https://github.com/radareorg/radare2#installation"],
  },
  managed: [brew("radare2")],
  commands: [
    ex("Analyze binary", "r2 -A {file}", "Open with full analysis."),
    ex("Binary info", "rabin2 -I {file}", "Show binary headers and protections."),
  ],
});
tool({
  id: "x64dbg", name: "x64dbg", category: "reversing", kind: "gui",
  description: "Open-source x64/x32 debugger for Windows focused on malware analysis and reverse engineering.",
  website: "https://x64dbg.com/", docs: "https://help.x64dbg.com/",
  os: ["windows"], tags: ["debugger", "windows"],
  detect: { binaries: ["x64dbg", "x96dbg"] },
  install: { windows: ["Download a snapshot from https://github.com/x64dbg/x64dbg/releases and add release\\x64 to PATH"] },
  commands: [ex("Launch", "x64dbg", "Start the debugger.")],
});
tool({
  id: "jadx", name: "JADX", category: "reversing",
  description: "Dex-to-Java decompiler producing readable Java source from Android APK and DEX files.",
  website: "https://github.com/skylot/jadx", docs: "https://github.com/skylot/jadx#readme",
  os: ALL, tags: ["android", "decompiler"],
  detect: { binaries: ["jadx"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a release from https://github.com/skylot/jadx/releases"],
    macos: ["brew install jadx"],
    linux: ["Download a release from https://github.com/skylot/jadx/releases"],
  },
  managed: [brew("jadx")],
  dependencies: [JAVA],
  commands: [ex("Decompile APK", "jadx -d {output} {apk}", "Decompile an APK into a directory.")],
});

/* ───────────────────────── Cryptography / TLS ───────────────────────── */
tool({
  id: "openssl", name: "OpenSSL", category: "crypto",
  description: "Toolkit for TLS and general-purpose cryptography: certificates, keys, digests and connection testing.",
  website: "https://www.openssl.org/", docs: "https://docs.openssl.org/master/man1/",
  os: ALL, tags: ["tls", "certificates", "crypto"],
  detect: { binaries: ["openssl"], versionArgs: ["version"] },
  install: {
    windows: ["Bundled with Git for Windows (usr\\bin\\openssl.exe), or see https://wiki.openssl.org/index.php/Binaries"],
    macos: ["brew install openssl@3"],
    linux: ["sudo apt install openssl"],
  },
  commands: [
    ex("Inspect certificate", "openssl s_client -connect {host}:443 -servername {host}", "Connect and print the server certificate chain."),
    ex("File digest", "openssl dgst -sha256 {file}", "Compute a SHA-256 digest."),
  ],
});
tool({
  id: "testssl", name: "testssl.sh", category: "crypto",
  description: "Command-line tool checking a server's TLS/SSL ciphers, protocols and known cryptographic flaws.",
  website: "https://testssl.sh/", docs: "https://testssl.sh/doc/testssl.1.html",
  os: UNIX, tags: ["tls", "audit"],
  detect: { binaries: ["testssl.sh", "testssl"] },
  install: { macos: ["brew install testssl"], linux: ["git clone --depth 1 https://github.com/testssl/testssl.sh.git"] },
  managed: [brew("testssl")],
  dependencies: [BASH],
  commands: [
    ex("Full check", "testssl.sh {host}:443", "Run all default checks."),
    ex("Protocols only", "testssl.sh -p {host}:443", "Check supported protocols."),
  ],
  requiresScope: true,
});
tool({
  id: "sslscan", name: "sslscan", category: "crypto",
  description: "Fast scanner listing a TLS server's supported protocols, ciphers and certificate details.",
  website: "https://github.com/rbsec/sslscan", docs: "https://github.com/rbsec/sslscan#readme",
  os: ALL, tags: ["tls", "ciphers"],
  detect: { binaries: ["sslscan"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a release from https://github.com/rbsec/sslscan/releases"],
    macos: ["brew install sslscan"],
    linux: ["sudo apt install sslscan"],
  },
  managed: [brew("sslscan")],
  commands: [ex("Scan host", "sslscan {host}:443", "List protocols and ciphers.")],
  requiresScope: true,
});
tool({
  id: "cyberchef", name: "CyberChef", category: "crypto", kind: "web",
  description: "GCHQ's web app for encoding, decoding, encryption, compression and data analysis. ExploitX also includes a local transformation workspace.",
  website: "https://gchq.github.io/CyberChef/", docs: "https://github.com/gchq/CyberChef/wiki",
  os: ALL, tags: ["encoding", "data", "web"],
  install: { windows: ["Web application, no installation required"], macos: ["Web application, no installation required"], linux: ["Web application, no installation required"] },
  commands: [],
});

/* ───────────────────────── Linux security ───────────────────────── */
tool({
  id: "lynis", name: "Lynis", category: "linux",
  description: "Security auditing tool for Linux, macOS and UNIX hosts that checks hardening and compliance.",
  website: "https://cisofy.com/lynis/", docs: "https://cisofy.com/documentation/lynis/",
  os: UNIX, tags: ["hardening", "audit", "compliance"],
  detect: { binaries: ["lynis"], versionArgs: ["show", "version"] },
  install: { macos: ["brew install lynis"], linux: ["sudo apt install lynis"] },
  managed: [brew("lynis")],
  commands: [ex("System audit", "sudo lynis audit system", "Audit the local host.")],
});
tool({
  id: "chkrootkit", name: "chkrootkit", category: "linux",
  description: "Locally checks for signs of known rootkits on UNIX systems.",
  website: "https://www.chkrootkit.org/", docs: "https://www.chkrootkit.org/README",
  os: LINUX, tags: ["rootkit", "integrity"],
  detect: { binaries: ["chkrootkit"] },
  install: { linux: ["sudo apt install chkrootkit"] },
  commands: [ex("Run checks", "sudo chkrootkit", "Run all checks.")],
});
tool({
  id: "rkhunter", name: "Rootkit Hunter", category: "linux",
  description: "Scans for rootkits, backdoors and local exploits by comparing file hashes and checking suspicious settings.",
  website: "https://rkhunter.sourceforge.net/", docs: "https://sourceforge.net/p/rkhunter/wiki/Home/",
  os: LINUX, tags: ["rootkit", "integrity"],
  detect: { binaries: ["rkhunter"], versionArgs: ["--version"] },
  install: { linux: ["sudo apt install rkhunter"] },
  commands: [
    ex("Update properties", "sudo rkhunter --propupd", "Record current file properties as a baseline."),
    ex("Check system", "sudo rkhunter --check --sk", "Run checks without pausing."),
  ],
});
tool({
  id: "peass", name: "PEASS-ng", category: "linux", kind: "script",
  description: "Privilege-escalation awareness scripts (LinPEAS/WinPEAS) that enumerate local misconfigurations during authorized assessments.",
  website: "https://github.com/peass-ng/PEASS-ng", docs: "https://github.com/peass-ng/PEASS-ng#readme",
  os: ALL, tags: ["privilege-escalation", "enumeration"],
  install: {
    windows: ["Download winPEAS from the GitHub releases page"],
    macos: ["Download linpeas.sh from the GitHub releases page"],
    linux: ["Download linpeas.sh from the GitHub releases page"],
  },
  commands: [ex("Local enumeration", "sh linpeas.sh", "Enumerate the local host (only on systems in scope).")],
});

/* ───────────────────────── Active Directory ───────────────────────── */
tool({
  id: "bloodhound", name: "BloodHound", category: "ad", kind: "gui",
  description: "Graph-based analysis of Active Directory and Entra ID relationships to identify and remediate attack paths.",
  website: "https://bloodhound.specterops.io/", docs: "https://bloodhound.specterops.io/get-started/introduction",
  os: ALL, tags: ["active-directory", "graph", "attack-paths"],
  detect: { binaries: ["BloodHound", "bloodhound"] },
  install: {
    windows: ["BloodHound Community Edition runs via Docker; see the quickstart at https://bloodhound.specterops.io/"],
    macos: ["BloodHound Community Edition runs via Docker; see the quickstart at https://bloodhound.specterops.io/"],
    linux: ["BloodHound Community Edition runs via Docker; see the quickstart at https://bloodhound.specterops.io/"],
  },
  commands: [],
});
tool({
  id: "netexec", name: "NetExec", category: "ad",
  description: "Network service assessment tool (successor of CrackMapExec) for SMB, LDAP, WinRM, MSSQL and more.",
  website: "https://www.netexec.wiki/", docs: "https://www.netexec.wiki/",
  os: ALL, tags: ["smb", "ldap", "active-directory"],
  detect: { binaries: ["netexec", "nxc"], versionArgs: ["--version"] },
  install: {
    windows: ["Download a release from https://github.com/Pennyw0rth/NetExec/releases"],
    macos: ["pipx install git+https://github.com/Pennyw0rth/NetExec"],
    linux: ["pipx install git+https://github.com/Pennyw0rth/NetExec"],
  },
  managed: [{ os: UNIX, manager: "pipx", args: ["install", "git+https://github.com/Pennyw0rth/NetExec"] }],
  dependencies: [PY],
  commands: [
    ex("SMB host info", "nxc smb {target}", "Fingerprint SMB hosts (OS, signing, domain)."),
    ex("List shares", "nxc smb {target} -u {user} -p {password} --shares", "List shares with provided credentials."),
  ],
  requiresScope: true,
});
tool({
  id: "impacket", name: "Impacket", category: "ad",
  description: "Python classes and example scripts for working with network protocols such as SMB, MSRPC, Kerberos and LDAP.",
  website: "https://github.com/fortra/impacket", docs: "https://github.com/fortra/impacket#readme",
  os: ALL, tags: ["smb", "kerberos", "python"],
  detect: { binaries: ["impacket-smbclient", "smbclient.py"] },
  install: { windows: ["pipx install impacket"], macos: ["pipx install impacket"], linux: ["pipx install impacket"] },
  managed: [pipx("impacket")],
  dependencies: [PY],
  commands: [
    ex("SMB client", "impacket-smbclient {domain}/{user}@{target}", "Interactive SMB client."),
    ex("Lookup SIDs", "impacket-lookupsid {domain}/{user}@{target}", "Enumerate users and groups via SID lookup."),
  ],
  requiresScope: true,
});
tool({
  id: "responder", name: "Responder", category: "ad",
  description: "LLMNR/NBT-NS/mDNS analyzer used to assess name-resolution poisoning exposure on internal networks.",
  website: "https://github.com/lgandx/Responder", docs: "https://github.com/lgandx/Responder#readme",
  os: UNIX, tags: ["llmnr", "network", "active-directory"],
  detect: { binaries: ["responder", "Responder.py"] },
  install: { macos: ["git clone https://github.com/lgandx/Responder"], linux: ["sudo apt install responder"] },
  dependencies: [PY],
  commands: [ex("Analyze mode (passive)", "sudo responder -I {interface} -A", "Listen and report requests without poisoning.")],
});
tool({
  id: "kerbrute", name: "Kerbrute", category: "ad",
  description: "Kerberos pre-authentication tool for validating Active Directory usernames during authorized assessments.",
  website: "https://github.com/ropnop/kerbrute", docs: "https://github.com/ropnop/kerbrute#readme",
  os: ALL, tags: ["kerberos", "active-directory"],
  detect: { binaries: ["kerbrute"], versionArgs: ["version"] },
  install: {
    windows: ["Download a release from https://github.com/ropnop/kerbrute/releases"],
    macos: ["go install github.com/ropnop/kerbrute@latest"],
    linux: ["go install github.com/ropnop/kerbrute@latest"],
  },
  managed: [go("github.com/ropnop/kerbrute@latest")],
  dependencies: [GOLANG],
  commands: [ex("Validate usernames", "kerbrute userenum -d {domain} --dc {dc} {userlist}", "Check which usernames exist.")],
  requiresScope: true,
});
tool({
  id: "evil-winrm", name: "Evil-WinRM", category: "ad",
  description: "WinRM shell for administrators and testers to manage Windows hosts with valid credentials.",
  website: "https://github.com/Hackplayers/evil-winrm", docs: "https://github.com/Hackplayers/evil-winrm#readme",
  os: UNIX, tags: ["winrm", "windows", "remote-management"],
  detect: { binaries: ["evil-winrm"] },
  install: { macos: ["gem install evil-winrm"], linux: ["sudo apt install evil-winrm", "Or: gem install evil-winrm"] },
  dependencies: [RUBY],
  commands: [ex("Connect", "evil-winrm -i {target} -u {user}", "Open a WinRM session (prompts for password).")],
  requiresScope: true,
});

/* ───────────────────────── Write ───────────────────────── */
const ids = new Set();
for (const t of tools) {
  if (ids.has(t.id)) throw new Error(`duplicate id ${t.id}`);
  ids.add(t.id);
  if (!categories.some((c) => c.id === t.category)) throw new Error(`bad category ${t.category} on ${t.id}`);
  if (t.detect?.versionRegex) new RegExp(t.detect.versionRegex);
}
const out = new URL("../src-tauri/catalog/tools.json", import.meta.url);
writeFileSync(out, JSON.stringify({ version: 1, categories, tools }, null, 2) + "\n");
console.log(`wrote ${tools.length} tools in ${categories.length} categories`);
