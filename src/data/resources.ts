// SPDX-License-Identifier: Apache-2.0
import type { Resource, ResourceCategory } from "@/types/catalog";

export const RESOURCE_CATEGORY_LABELS: Record<ResourceCategory, string> = {
  learning: "Learning",
  intelligence: "Threat intelligence",
  documentation: "Documentation",
  "vulnerability-databases": "Vulnerability databases",
  "tools-online": "Online tools",
  community: "Community",
};

const r = (id: string, title: string, url: string, category: ResourceCategory, description: string, tags: string[]): Resource => ({
  id,
  title,
  url,
  category,
  description,
  tags,
});

export const RESOURCES: Resource[] = [
  // Learning
  r("portswigger-academy", "PortSwigger Web Security Academy", "https://portswigger.net/web-security", "learning", "Free, hands-on web security training with interactive labs for every major vulnerability class.", ["web", "labs", "free"]),
  r("owasp", "OWASP Foundation", "https://owasp.org/", "learning", "Open community producing application security standards, tools and guidance.", ["web", "standards"]),
  r("owasp-top10", "OWASP Top 10", "https://owasp.org/www-project-top-ten/", "learning", "Awareness document of the most critical web application security risks.", ["web", "risk"]),
  r("owasp-wstg", "OWASP Web Security Testing Guide", "https://owasp.org/www-project-web-security-testing-guide/", "learning", "Comprehensive methodology for testing web applications and services.", ["web", "methodology"]),
  r("htb", "Hack The Box", "https://www.hackthebox.com/", "learning", "Gamified penetration testing labs, machines and professional training paths.", ["labs", "ctf"]),
  r("thm", "TryHackMe", "https://tryhackme.com/", "learning", "Guided, browser-based cybersecurity learning rooms for beginners to advanced.", ["labs", "beginner"]),
  r("hacktricks", "HackTricks", "https://book.hacktricks.wiki/", "learning", "Community wiki of pentesting techniques, checklists and methodology notes.", ["methodology", "wiki"]),
  r("payloadsallthethings", "PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings", "learning", "Large reference of payloads and bypasses for web application testing.", ["payloads", "web"]),
  r("pentesterlab", "PentesterLab", "https://pentesterlab.com/", "learning", "Exercises focused on understanding and exploiting real-world web vulnerabilities.", ["web", "labs"]),
  r("overthewire", "OverTheWire Wargames", "https://overthewire.org/wargames/", "learning", "Classic wargames teaching Linux, networking and security fundamentals.", ["linux", "ctf"]),
  r("picoctf", "picoCTF", "https://picoctf.org/", "learning", "Carnegie Mellon's free capture-the-flag platform and practice gym.", ["ctf", "beginner"]),
  r("bugcrowd-university", "Bugcrowd University", "https://www.bugcrowd.com/hackers/bugcrowd-university/", "learning", "Free training content for bug bounty hunters.", ["bug-bounty"]),

  // Threat intelligence
  r("mitre-attack", "MITRE ATT&CK", "https://attack.mitre.org/", "intelligence", "Knowledge base of adversary tactics and techniques based on real-world observations.", ["ttp", "framework"]),
  r("virustotal", "VirusTotal", "https://www.virustotal.com/", "intelligence", "Analyze files, URLs, domains and IPs with multiple antivirus engines and sandboxes.", ["malware", "reputation"]),
  r("shodan", "Shodan", "https://www.shodan.io/", "intelligence", "Search engine for Internet-connected devices and exposed services.", ["exposure", "iot"]),
  r("censys", "Censys Search", "https://search.censys.io/", "intelligence", "Internet-wide scan data on hosts, certificates and services.", ["exposure", "certificates"]),
  r("urlscan", "urlscan.io", "https://urlscan.io/", "intelligence", "Sandbox that scans and records what a website loads and contacts.", ["urls", "phishing"]),
  r("crtsh", "crt.sh", "https://crt.sh/", "intelligence", "Certificate Transparency log search — useful for discovering subdomains.", ["certificates", "recon"]),
  r("securitytrails", "SecurityTrails", "https://securitytrails.com/", "intelligence", "Historical DNS, WHOIS and domain intelligence.", ["dns", "history"]),
  r("abuseipdb", "AbuseIPDB", "https://www.abuseipdb.com/", "intelligence", "Community database of IP addresses reported for abusive behavior.", ["ip", "reputation"]),
  r("greynoise", "GreyNoise", "https://viz.greynoise.io/", "intelligence", "Identifies Internet background noise and mass-scanning IP addresses.", ["ip", "scanners"]),
  r("dnsdumpster", "DNSDumpster", "https://dnsdumpster.com/", "intelligence", "Free domain research tool mapping DNS records and hosts.", ["dns", "recon"]),
  r("wayback", "Wayback Machine", "https://web.archive.org/", "intelligence", "Archived snapshots of websites over time.", ["archive", "osint"]),

  // Vulnerability databases
  r("nvd", "NIST National Vulnerability Database", "https://nvd.nist.gov/", "vulnerability-databases", "U.S. government repository of CVE records with CVSS scoring and CPE data.", ["cve", "cvss"]),
  r("cve-org", "CVE Program", "https://www.cve.org/", "vulnerability-databases", "Official catalog of publicly disclosed cybersecurity vulnerabilities.", ["cve"]),
  r("cisa-kev", "CISA Known Exploited Vulnerabilities", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "vulnerability-databases", "Authoritative list of vulnerabilities known to be exploited in the wild.", ["cve", "prioritization"]),
  r("exploit-db", "Exploit Database", "https://www.exploit-db.com/", "vulnerability-databases", "Archive of public exploits and vulnerable software, maintained by OffSec.", ["exploits"]),
  r("github-advisories", "GitHub Advisory Database", "https://github.com/advisories", "vulnerability-databases", "Security advisories for open-source ecosystems, linked to CVEs.", ["dependencies", "oss"]),
  r("osv", "OSV.dev", "https://osv.dev/", "vulnerability-databases", "Distributed vulnerability database for open-source packages.", ["dependencies", "oss"]),
  r("mitre-cwe", "MITRE CWE", "https://cwe.mitre.org/", "vulnerability-databases", "Community list of software and hardware weakness types.", ["cwe", "taxonomy"]),

  // Documentation
  r("kali-tools", "Kali Linux Tools", "https://www.kali.org/tools/", "documentation", "Documentation and usage notes for every tool packaged in Kali Linux.", ["tools", "linux"]),
  r("owasp-cheatsheets", "OWASP Cheat Sheet Series", "https://cheatsheetseries.owasp.org/", "documentation", "Concise, actionable guidance on specific application security topics.", ["web", "defense"]),
  r("owasp-asvs", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/", "documentation", "Application Security Verification Standard for testing technical controls.", ["standards", "verification"]),
  r("mdn", "MDN Web Docs", "https://developer.mozilla.org/", "documentation", "Reference documentation for HTML, CSS, JavaScript and HTTP.", ["web", "http"]),
  r("python-docs", "Python Documentation", "https://docs.python.org/3/", "documentation", "Official Python 3 language and standard library reference.", ["python"]),
  r("man7", "Linux man pages (man7.org)", "https://man7.org/linux/man-pages/", "documentation", "Online Linux manual pages for commands, system calls and libraries.", ["linux"]),
  r("gtfobins", "GTFOBins", "https://gtfobins.github.io/", "documentation", "Curated list of Unix binaries and how they can be misused when misconfigured.", ["linux", "privilege-escalation"]),
  r("lolbas", "LOLBAS", "https://lolbas-project.github.io/", "documentation", "Living-off-the-land binaries, scripts and libraries on Windows.", ["windows", "detection"]),
  r("sans-reading-room", "SANS Reading Room", "https://www.sans.org/white-papers/", "documentation", "Library of security white papers written by practitioners.", ["research", "papers"]),

  // Online tools
  r("cyberchef", "CyberChef", "https://gchq.github.io/CyberChef/", "tools-online", "GCHQ's web app for encoding, decoding, encryption and data analysis.", ["encoding", "data"]),
  r("explainshell", "ExplainShell", "https://explainshell.com/", "tools-online", "Breaks down shell commands and shows the help text for each argument.", ["shell", "learning"]),
  r("regex101", "regex101", "https://regex101.com/", "tools-online", "Online regular expression tester and debugger with explanations.", ["regex"]),
  r("jwt-io", "JWT.io", "https://jwt.io/", "tools-online", "Decode and inspect JSON Web Tokens (ExploitX includes a local decoder).", ["jwt", "auth"]),

  // Community
  r("hackerone-hacktivity", "HackerOne Hacktivity", "https://hackerone.com/hacktivity", "community", "Disclosed bug bounty reports — learn from real findings.", ["bug-bounty", "reports"]),
  r("reddit-netsec", "r/netsec", "https://www.reddit.com/r/netsec/", "community", "Technical information security news and research discussions.", ["news", "research"]),
  r("owasp-chapters", "OWASP Community Chapters", "https://owasp.org/chapters/", "community", "Local OWASP chapters and meetups worldwide.", ["meetups"]),
];
