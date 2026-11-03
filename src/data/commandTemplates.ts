import type { CommandTemplate, CommandVariable } from "@/types/catalog";

export const COMMAND_TEMPLATE_CATEGORIES = [
  "Network Discovery",
  "Web Enumeration",
  "Subdomain Recon",
  "Vulnerability Scanning",
  "Password Auditing",
  "Forensics",
  "TLS/Crypto",
  "Linux System",
  "Windows System",
  "Utilities",
] as const;

const v = (name: string, label: string, placeholder: string, def?: string): CommandVariable => ({ name, label, placeholder, default: def });
const x = (part: string, meaning: string) => ({ part, meaning });

const TARGET = v("target", "Target", "10.0.0.5 or host.example.com");
const DOMAIN = v("domain", "Domain", "example.com");
const URL = v("url", "Base URL", "https://app.example.com");
const WORDLIST = v("wordlist", "Wordlist path", "/usr/share/wordlists/dirb/common.txt");
const FILE = v("file", "File path", "./sample.bin");

export const COMMAND_TEMPLATES: CommandTemplate[] = [
  // Network discovery
  {
    id: "nmap-ping-sweep", title: "Host discovery sweep", category: "Network Discovery", tool: "nmap", os: "any",
    template: "nmap -sn {{range}}", description: "Find live hosts in a range without port scanning.",
    explanation: [x("-sn", "Ping scan only — skip port scanning"), x("{{range}}", "CIDR or range to sweep")],
    variables: [v("range", "Range", "10.0.0.0/24")],
  },
  {
    id: "nmap-top-ports", title: "Top 1000 ports with versions", category: "Network Discovery", tool: "nmap", os: "any",
    template: "nmap -sV -T4 {{target}} -oN {{output}}", description: "Service/version detection on the default 1000 ports, saved to a file.",
    explanation: [x("-sV", "Probe open ports for service and version"), x("-T4", "Faster timing template"), x("-oN", "Write normal output to a file")],
    variables: [TARGET, v("output", "Output file", "nmap-top.txt", "nmap-top.txt")],
  },
  {
    id: "nmap-full-tcp", title: "All TCP ports", category: "Network Discovery", tool: "nmap", os: "any",
    template: "nmap -p- --min-rate {{rate}} -T4 {{target}}", description: "Scan all 65535 TCP ports.",
    explanation: [x("-p-", "All ports 1-65535"), x("--min-rate", "Minimum packets per second")],
    variables: [TARGET, v("rate", "Min rate", "1000", "1000")],
  },
  {
    id: "nmap-udp-top", title: "Top UDP ports", category: "Network Discovery", tool: "nmap", os: "any",
    template: "sudo nmap -sU --top-ports {{count}} {{target}}", description: "UDP scan of the most common ports (requires privileges).",
    explanation: [x("-sU", "UDP scan"), x("--top-ports", "Scan the N most common ports")],
    variables: [TARGET, v("count", "Port count", "100", "100")],
  },
  {
    id: "nmap-scripts-safe", title: "Default safe scripts", category: "Network Discovery", tool: "nmap", os: "any",
    template: "nmap -sC -sV -p {{ports}} {{target}}", description: "Run default NSE scripts against specific ports.",
    explanation: [x("-sC", "Run the default (safe) NSE script set"), x("-p", "Comma-separated ports")],
    variables: [TARGET, v("ports", "Ports", "22,80,443", "22,80,443")],
  },
  {
    id: "rustscan-quick", title: "RustScan into Nmap", category: "Network Discovery", tool: "rustscan", os: "any",
    template: "rustscan -a {{target}} --ulimit 5000 -- -sV", description: "Fast port discovery, then hand open ports to Nmap for versioning.",
    explanation: [x("-a", "Address to scan"), x("--ulimit", "File descriptor limit for speed"), x("-- -sV", "Arguments passed to Nmap")],
    variables: [TARGET],
  },
  {
    id: "masscan-range", title: "Masscan port range", category: "Network Discovery", tool: "masscan", os: "any",
    template: "sudo masscan {{range}} -p{{ports}} --rate {{rate}}", description: "High-speed scan of a range for selected ports.",
    explanation: [x("-p", "Ports or ranges"), x("--rate", "Packets per second — keep conservative")],
    variables: [v("range", "Range", "10.0.0.0/24"), v("ports", "Ports", "80,443", "80,443"), v("rate", "Rate", "1000", "1000")],
  },
  {
    id: "tcpdump-host", title: "Capture traffic for a host", category: "Network Discovery", tool: "tcpdump", os: "linux",
    template: "sudo tcpdump -i {{iface}} host {{target}} -w {{output}}", description: "Write packets to/from one host to a pcap.",
    explanation: [x("-i", "Capture interface"), x("host", "BPF filter for one address"), x("-w", "Write raw packets to file")],
    variables: [v("iface", "Interface", "eth0", "eth0"), TARGET, v("output", "Output pcap", "capture.pcap", "capture.pcap")],
  },

  // Web enumeration
  {
    id: "ffuf-dirs", title: "Directory discovery", category: "Web Enumeration", tool: "ffuf", os: "any",
    template: "ffuf -u {{url}}/FUZZ -w {{wordlist}} -mc 200,204,301,302,307,401,403 -t 40", description: "Fuzz paths and keep interesting status codes.",
    explanation: [x("-u", "URL with FUZZ keyword"), x("-w", "Wordlist"), x("-mc", "Match status codes"), x("-t", "Concurrent threads")],
    variables: [URL, WORDLIST],
  },
  {
    id: "ffuf-params", title: "GET parameter discovery", category: "Web Enumeration", tool: "ffuf", os: "any",
    template: "ffuf -u '{{url}}?FUZZ=test' -w {{wordlist}} -fs {{size}}", description: "Discover hidden parameters by filtering the baseline response size.",
    explanation: [x("FUZZ=test", "Parameter name is fuzzed"), x("-fs", "Filter responses of the baseline size")],
    variables: [URL, WORDLIST, v("size", "Baseline size", "4242")],
  },
  {
    id: "gobuster-dir", title: "Gobuster directories with extensions", category: "Web Enumeration", tool: "gobuster", os: "any",
    template: "gobuster dir -u {{url}} -w {{wordlist}} -x {{ext}} -t 30", description: "Enumerate files and directories with extensions.",
    explanation: [x("dir", "Directory/file mode"), x("-x", "Extensions to append"), x("-t", "Threads")],
    variables: [URL, WORDLIST, v("ext", "Extensions", "php,txt,bak", "php,txt,bak")],
  },
  {
    id: "httpx-probe", title: "Probe live web hosts", category: "Web Enumeration", tool: "httpx", os: "any",
    template: "httpx -l {{hosts}} -sc -title -tech-detect -o {{output}}", description: "Check which hosts serve HTTP and fingerprint them.",
    explanation: [x("-l", "File with hosts"), x("-sc", "Show status code"), x("-title", "Page title"), x("-tech-detect", "Wappalyzer-based tech detection")],
    variables: [v("hosts", "Hosts file", "hosts.txt"), v("output", "Output file", "httpx.txt", "httpx.txt")],
  },
  {
    id: "nikto-basic", title: "Nikto web server check", category: "Web Enumeration", tool: "nikto", os: "any",
    template: "nikto -h {{url}} -o {{output}}", description: "Check a web server for dangerous files and outdated software.",
    explanation: [x("-h", "Target host or URL"), x("-o", "Output report file")],
    variables: [URL, v("output", "Report file", "nikto.html", "nikto.html")],
  },
  {
    id: "whatweb-fp", title: "Fingerprint technologies", category: "Web Enumeration", tool: "whatweb", os: "linux",
    template: "whatweb -a 1 {{url}}", description: "Identify CMS, frameworks and server software.",
    explanation: [x("-a 1", "Stealthy aggression level (single request)")],
    variables: [URL],
  },
  {
    id: "curl-headers", title: "Inspect response headers", category: "Web Enumeration", os: "any",
    template: "curl -sS -I {{url}}", description: "Fetch only response headers.",
    explanation: [x("-sS", "Silent but show errors"), x("-I", "HEAD request (headers only)")],
    variables: [URL],
  },
  {
    id: "katana-crawl", title: "Crawl a web application", category: "Web Enumeration", tool: "katana", os: "any",
    template: "katana -u {{url}} -d {{depth}} -o {{output}}", description: "Crawl and list discovered endpoints.",
    explanation: [x("-d", "Maximum crawl depth"), x("-o", "Output file")],
    variables: [URL, v("depth", "Depth", "3", "3"), v("output", "Output file", "endpoints.txt", "endpoints.txt")],
  },

  // Subdomain recon
  {
    id: "subfinder-basic", title: "Passive subdomain enumeration", category: "Subdomain Recon", tool: "subfinder", os: "any",
    template: "subfinder -d {{domain}} -all -silent -o {{output}}", description: "Collect subdomains from passive sources.",
    explanation: [x("-d", "Root domain"), x("-all", "Use all sources"), x("-silent", "Only print results")],
    variables: [DOMAIN, v("output", "Output file", "subs.txt", "subs.txt")],
  },
  {
    id: "amass-passive", title: "Amass passive enumeration", category: "Subdomain Recon", tool: "amass", os: "any",
    template: "amass enum -passive -d {{domain}} -o {{output}}", description: "Passive OWASP Amass enumeration.",
    explanation: [x("enum -passive", "No direct contact with target infrastructure"), x("-o", "Output file")],
    variables: [DOMAIN, v("output", "Output file", "amass.txt", "amass.txt")],
  },
  {
    id: "dnsx-resolve", title: "Resolve subdomain list", category: "Subdomain Recon", tool: "dnsx", os: "any",
    template: "dnsx -l {{input}} -a -resp -o {{output}}", description: "Resolve hosts and keep A records.",
    explanation: [x("-l", "Input list"), x("-a", "Query A records"), x("-resp", "Print responses")],
    variables: [v("input", "Input list", "subs.txt", "subs.txt"), v("output", "Output file", "resolved.txt", "resolved.txt")],
  },
  {
    id: "dig-any", title: "DNS records with dig", category: "Subdomain Recon", os: "linux",
    template: "dig +noall +answer {{domain}} {{type}}", description: "Query a specific DNS record type.",
    explanation: [x("+noall +answer", "Only print the answer section"), x("{{type}}", "A, AAAA, MX, TXT, NS…")],
    variables: [DOMAIN, v("type", "Record type", "MX", "MX")],
  },
  {
    id: "nslookup-win", title: "DNS records with nslookup", category: "Subdomain Recon", os: "windows",
    template: "nslookup -type={{type}} {{domain}}", description: "Query a DNS record type on Windows.",
    explanation: [x("-type", "Record type to query")],
    variables: [DOMAIN, v("type", "Record type", "MX", "MX")],
  },
  {
    id: "crtsh-curl", title: "Certificate transparency subdomains", category: "Subdomain Recon", os: "linux",
    template: "curl -s 'https://crt.sh/?q=%25.{{domain}}&output=json' | jq -r '.[].name_value' | sort -u", description: "List names from CT logs via crt.sh.",
    explanation: [x("%25.", "URL-encoded % wildcard"), x("jq -r", "Extract names"), x("sort -u", "Deduplicate")],
    variables: [DOMAIN],
  },

  // Vulnerability scanning
  {
    id: "nuclei-cves", title: "Nuclei CVE templates", category: "Vulnerability Scanning", tool: "nuclei", os: "any",
    template: "nuclei -u {{url}} -tags cve -severity {{severity}}", description: "Run CVE templates at selected severities.",
    explanation: [x("-tags cve", "Only CVE templates"), x("-severity", "Comma-separated severities")],
    variables: [URL, v("severity", "Severities", "critical,high", "critical,high")],
  },
  {
    id: "nuclei-list", title: "Nuclei on a host list", category: "Vulnerability Scanning", tool: "nuclei", os: "any",
    template: "nuclei -l {{hosts}} -rl {{rate}} -o {{output}}", description: "Scan many hosts with a rate limit.",
    explanation: [x("-l", "Targets file"), x("-rl", "Requests per second"), x("-o", "Output file")],
    variables: [v("hosts", "Hosts file", "live.txt"), v("rate", "Rate limit", "50", "50"), v("output", "Output file", "nuclei.txt", "nuclei.txt")],
  },
  {
    id: "searchsploit-term", title: "Search local exploit archive", category: "Vulnerability Scanning", tool: "searchsploit", os: "linux",
    template: "searchsploit {{term}}", description: "Look up public exploits for a product/version.",
    explanation: [x("{{term}}", "Product and version keywords")],
    variables: [v("term", "Search terms", "apache 2.4.49")],
  },
  {
    id: "sqlmap-basic", title: "SQLmap on a parameter", category: "Vulnerability Scanning", tool: "sqlmap", os: "any",
    template: "sqlmap -u '{{url}}' -p {{param}} --batch --level 1 --risk 1", description: "Test one parameter with the lowest level and risk.",
    explanation: [x("-p", "Parameter to test"), x("--batch", "Use defaults, no prompts"), x("--level/--risk 1", "Least intrusive test set")],
    variables: [v("url", "URL with parameter", "https://app.example.com/item?id=1"), v("param", "Parameter", "id", "id")],
  },
  {
    id: "trivy-image", title: "Scan a container image", category: "Vulnerability Scanning", tool: "trivy", os: "any",
    template: "trivy image --severity {{severity}} {{image}}", description: "List vulnerable packages in an image.",
    explanation: [x("--severity", "Filter by severity")],
    variables: [v("image", "Image", "nginx:latest"), v("severity", "Severities", "HIGH,CRITICAL", "HIGH,CRITICAL")],
  },

  // Password auditing
  {
    id: "hashcat-identify", title: "Identify hash mode", category: "Password Auditing", tool: "hashcat", os: "any",
    template: "hashcat --identify {{hashfile}}", description: "Let hashcat suggest matching hash modes.",
    explanation: [x("--identify", "Detect candidate modes")],
    variables: [v("hashfile", "Hash file", "hashes.txt")],
  },
  {
    id: "hashcat-wordlist", title: "Wordlist audit", category: "Password Auditing", tool: "hashcat", os: "any",
    template: "hashcat -m {{mode}} -a 0 {{hashfile}} {{wordlist}}", description: "Audit hashes you are authorized to test against a wordlist.",
    explanation: [x("-m", "Hash mode (e.g. 1000 = NTLM)"), x("-a 0", "Straight/dictionary attack mode")],
    variables: [v("mode", "Hash mode", "1000"), v("hashfile", "Hash file", "hashes.txt"), WORDLIST],
  },
  {
    id: "john-show", title: "Show recovered passwords", category: "Password Auditing", tool: "john", os: "any",
    template: "john --show {{hashfile}}", description: "Display passwords already recovered for a hash file.",
    explanation: [x("--show", "Read results from the pot file")],
    variables: [v("hashfile", "Hash file", "hashes.txt")],
  },

  // Forensics
  {
    id: "exiftool-all", title: "Extract file metadata", category: "Forensics", tool: "exiftool", os: "any",
    template: "exiftool -a -G1 {{file}}", description: "Show all metadata with group names.",
    explanation: [x("-a", "Allow duplicate tags"), x("-G1", "Show specific group for each tag")],
    variables: [FILE],
  },
  {
    id: "strings-min", title: "Printable strings", category: "Forensics", os: "linux",
    template: "strings -n {{min}} {{file}} | less", description: "List printable strings of at least N characters.",
    explanation: [x("-n", "Minimum string length")],
    variables: [FILE, v("min", "Minimum length", "8", "8")],
  },
  {
    id: "vol-pslist", title: "Memory image process list", category: "Forensics", tool: "volatility3", os: "any",
    template: "vol -f {{memdump}} windows.pslist", description: "List processes in a Windows memory image.",
    explanation: [x("-f", "Memory image"), x("windows.pslist", "Plugin to walk the process list")],
    variables: [v("memdump", "Memory image", "memory.raw")],
  },
  {
    id: "binwalk-scan", title: "Firmware signature scan", category: "Forensics", tool: "binwalk", os: "linux",
    template: "binwalk {{file}}", description: "Identify embedded files and filesystems.",
    explanation: [x("{{file}}", "Firmware or binary blob")],
    variables: [FILE],
  },

  // TLS / crypto
  {
    id: "openssl-cert", title: "Show server certificate", category: "TLS/Crypto", tool: "openssl", os: "any",
    template: "openssl s_client -connect {{host}}:443 -servername {{host}} -showcerts", description: "Connect and print the presented certificate chain.",
    explanation: [x("-servername", "Send SNI"), x("-showcerts", "Print the full chain")],
    variables: [v("host", "Host", "example.com")],
  },
  {
    id: "testssl-full", title: "TLS configuration audit", category: "TLS/Crypto", tool: "testssl", os: "linux",
    template: "testssl.sh {{host}}:443", description: "Check protocols, ciphers and known TLS flaws.",
    explanation: [x("{{host}}:443", "Host and port")],
    variables: [v("host", "Host", "example.com")],
  },
  {
    id: "sha256-linux", title: "SHA-256 of a file", category: "TLS/Crypto", os: "linux",
    template: "sha256sum {{file}}", description: "Compute a SHA-256 checksum.",
    explanation: [x("sha256sum", "Coreutils hashing tool")],
    variables: [FILE],
  },
  {
    id: "sha256-macos", title: "SHA-256 of a file", category: "TLS/Crypto", os: "macos",
    template: "shasum -a 256 {{file}}", description: "Compute a SHA-256 checksum on macOS.",
    explanation: [x("-a 256", "Use SHA-256")],
    variables: [FILE],
  },
  {
    id: "sha256-windows", title: "SHA-256 of a file", category: "TLS/Crypto", os: "windows",
    template: "certutil -hashfile {{file}} SHA256", description: "Compute a SHA-256 checksum on Windows.",
    explanation: [x("-hashfile", "Hash a file"), x("SHA256", "Algorithm")],
    variables: [FILE],
  },

  // Linux system
  {
    id: "ss-listen", title: "Listening sockets", category: "Linux System", os: "linux",
    template: "sudo ss -tulpn", description: "List listening TCP/UDP sockets with owning processes.",
    explanation: [x("-t/-u", "TCP and UDP"), x("-l", "Listening only"), x("-p", "Show process"), x("-n", "Numeric")],
    variables: [],
  },
  {
    id: "find-suid", title: "SUID binaries", category: "Linux System", os: "linux",
    template: "find / -perm -4000 -type f 2>/dev/null", description: "Audit set-user-ID executables on a host you manage.",
    explanation: [x("-perm -4000", "SUID bit set"), x("2>/dev/null", "Hide permission errors")],
    variables: [],
  },
  {
    id: "last-logins", title: "Recent logins", category: "Linux System", os: "linux",
    template: "last -n {{count}}", description: "Show recent login sessions.",
    explanation: [x("-n", "Number of entries")],
    variables: [v("count", "Entries", "20", "20")],
  },
  {
    id: "lsof-net", title: "Processes with network connections", category: "Linux System", os: "macos",
    template: "sudo lsof -i -P -n", description: "List open network files on macOS/Linux.",
    explanation: [x("-i", "Network files"), x("-P -n", "Numeric ports and hosts")],
    variables: [],
  },

  // Windows system
  {
    id: "netstat-ano", title: "Connections with PIDs", category: "Windows System", os: "windows",
    template: "netstat -ano", description: "List connections and listening ports with owning process IDs.",
    explanation: [x("-a", "All connections"), x("-n", "Numeric"), x("-o", "Owning PID")],
    variables: [],
  },
  {
    id: "ps-tcp", title: "Listening TCP ports (PowerShell)", category: "Windows System", os: "windows",
    template: "Get-NetTCPConnection -State Listen | Sort-Object LocalPort", description: "PowerShell view of listening TCP ports.",
    explanation: [x("-State Listen", "Only listening sockets")],
    variables: [],
  },
  {
    id: "ipconfig-all", title: "Network configuration", category: "Windows System", os: "windows",
    template: "ipconfig /all", description: "Show adapters, DNS servers and DHCP details.",
    explanation: [x("/all", "Full configuration")],
    variables: [],
  },
  {
    id: "ps-defender", title: "Defender status", category: "Windows System", os: "windows",
    template: "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated", description: "Check Microsoft Defender protection state.",
    explanation: [x("Get-MpComputerStatus", "Defender status cmdlet")],
    variables: [],
  },

  // Utilities
  {
    id: "python-http", title: "Serve a folder over HTTP", category: "Utilities", os: "any",
    template: "python3 -m http.server {{port}} --bind 127.0.0.1", description: "Quick local file server bound to loopback.",
    explanation: [x("-m http.server", "Standard-library HTTP server"), x("--bind", "Listen address")],
    variables: [v("port", "Port", "8000", "8000")],
  },
  {
    id: "base64-decode", title: "Decode base64 file", category: "Utilities", os: "linux",
    template: "base64 -d {{file}} > {{output}}", description: "Decode a base64 file to binary.",
    explanation: [x("-d", "Decode")],
    variables: [FILE, v("output", "Output file", "decoded.bin", "decoded.bin")],
  },
];
