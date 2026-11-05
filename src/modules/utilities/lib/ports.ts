/** Offline reference of common ports: what usually runs there and what to check. */
export interface PortInfo {
  port: number;
  proto: "tcp" | "udp" | "tcp/udp";
  service: string;
  description: string;
  /** what typically goes wrong when it is exposed */
  risks: string[];
  /** checks worth doing (all within the authorized scope) */
  checks: string[];
}

export const PORTS: PortInfo[] = [
  { port: 21, proto: "tcp", service: "FTP", description: "File transfer, credentials and data in clear text.", risks: ["Anonymous login", "Clear-text credentials", "Writable directories"], checks: ["Test anonymous login", "Prefer SFTP/FTPS"] },
  { port: 22, proto: "tcp", service: "SSH", description: "Remote shell and file transfer.", risks: ["Password authentication exposed to brute force", "Outdated OpenSSH versions", "Weak key exchange or ciphers"], checks: ["Confirm key-only authentication", "Check the version against CVEs", "Review allowed algorithms"] },
  { port: 23, proto: "tcp", service: "Telnet", description: "Unencrypted remote shell.", risks: ["Clear-text credentials", "Default device passwords"], checks: ["Replace with SSH", "Check for default credentials (authorized)"] },
  { port: 25, proto: "tcp", service: "SMTP", description: "Mail transfer between servers.", risks: ["Open relay", "User enumeration (VRFY/EXPN)", "Missing STARTTLS"], checks: ["Test for open relay", "Check STARTTLS and certificate", "Review SPF/DMARC (DNS intelligence)"] },
  { port: 53, proto: "tcp/udp", service: "DNS", description: "Name resolution.", risks: ["Open recursive resolver (amplification)", "Zone transfer (AXFR) allowed", "Outdated server software"], checks: ["Test recursion from outside", "Test AXFR against the authorized zone"] },
  { port: 80, proto: "tcp", service: "HTTP", description: "Unencrypted web traffic.", risks: ["No redirect to HTTPS", "Sensitive content without TLS", "Default or admin pages"], checks: ["Check the redirect to HTTPS", "Review security headers", "Look for default and admin paths"] },
  { port: 88, proto: "tcp/udp", service: "Kerberos", description: "Active Directory authentication.", risks: ["AS-REP roasting", "Kerberoasting", "User enumeration"], checks: ["Expected only on domain controllers", "Review accounts without pre-authentication"] },
  { port: 110, proto: "tcp", service: "POP3", description: "Mail retrieval.", risks: ["Clear-text credentials"], checks: ["Prefer POP3S (995)"] },
  { port: 111, proto: "tcp/udp", service: "RPCbind", description: "Maps ONC RPC services (NFS and others).", risks: ["Information disclosure", "Exposed NFS"], checks: ["List registered services", "Restrict to internal networks"] },
  { port: 135, proto: "tcp", service: "MS-RPC", description: "Windows RPC endpoint mapper.", risks: ["Enumeration of RPC services", "Should not be reachable from the internet"], checks: ["Restrict to internal networks"] },
  { port: 137, proto: "udp", service: "NetBIOS-NS", description: "NetBIOS name service.", risks: ["Name and domain disclosure", "Spoofing (NBT-NS poisoning) on local networks"], checks: ["Disable NetBIOS over TCP/IP where possible"] },
  { port: 139, proto: "tcp", service: "NetBIOS-SSN", description: "Legacy SMB session service.", risks: ["SMBv1", "Null sessions"], checks: ["Disable SMBv1", "Test null sessions"] },
  { port: 143, proto: "tcp", service: "IMAP", description: "Mail access.", risks: ["Clear-text credentials"], checks: ["Prefer IMAPS (993)"] },
  { port: 161, proto: "udp", service: "SNMP", description: "Device monitoring and management.", risks: ["Default community strings (public/private)", "SNMPv1/v2c without encryption", "Write access"], checks: ["Test default community strings (authorized)", "Prefer SNMPv3"] },
  { port: 389, proto: "tcp/udp", service: "LDAP", description: "Directory access.", risks: ["Anonymous bind", "Clear-text binds", "Missing LDAP signing"], checks: ["Test anonymous bind", "Prefer LDAPS (636) and signing"] },
  { port: 443, proto: "tcp", service: "HTTPS", description: "Encrypted web traffic.", risks: ["Weak or expired certificates", "Outdated TLS", "Application vulnerabilities"], checks: ["Run the TLS analyzer", "Review security headers", "Test the application"] },
  { port: 445, proto: "tcp", service: "SMB", description: "Windows file sharing.", risks: ["SMBv1 (EternalBlue)", "Missing SMB signing", "Open shares", "Never expose to the internet"], checks: ["Check SMB signing and versions", "List shares with authorization"] },
  { port: 465, proto: "tcp", service: "SMTPS", description: "SMTP over implicit TLS.", risks: ["Weak TLS", "Authentication brute force"], checks: ["Run the TLS analyzer"] },
  { port: 500, proto: "udp", service: "IKE", description: "IPsec VPN key exchange.", risks: ["Aggressive mode PSK cracking", "Weak proposals"], checks: ["Check for aggressive mode", "Review proposals"] },
  { port: 587, proto: "tcp", service: "Submission", description: "Mail submission by clients.", risks: ["Authentication brute force", "Missing STARTTLS"], checks: ["Check STARTTLS"] },
  { port: 636, proto: "tcp", service: "LDAPS", description: "LDAP over TLS.", risks: ["Anonymous bind", "Weak TLS"], checks: ["Run the TLS analyzer", "Test anonymous bind"] },
  { port: 993, proto: "tcp", service: "IMAPS", description: "IMAP over TLS.", risks: ["Weak TLS", "Authentication brute force"], checks: ["Run the TLS analyzer"] },
  { port: 995, proto: "tcp", service: "POP3S", description: "POP3 over TLS.", risks: ["Weak TLS"], checks: ["Run the TLS analyzer"] },
  { port: 1433, proto: "tcp", service: "MS SQL", description: "Microsoft SQL Server.", risks: ["Database exposed to the network", "Weak sa password", "xp_cmdshell"], checks: ["Restrict access", "Check authentication mode"] },
  { port: 1521, proto: "tcp", service: "Oracle TNS", description: "Oracle database listener.", risks: ["Database exposed", "Default accounts", "SID enumeration"], checks: ["Restrict access", "Check default accounts (authorized)"] },
  { port: 2049, proto: "tcp/udp", service: "NFS", description: "Network file system.", risks: ["World-readable exports", "no_root_squash"], checks: ["List exports", "Review export options"] },
  { port: 2375, proto: "tcp", service: "Docker API", description: "Docker daemon without TLS.", risks: ["Unauthenticated remote control equals root on the host"], checks: ["Never expose; require TLS (2376) and client certificates"] },
  { port: 3000, proto: "tcp", service: "Dev web servers", description: "Grafana, Node.js and other development servers.", risks: ["Debug or development mode in production", "Default credentials"], checks: ["Identify the application", "Check default credentials (authorized)"] },
  { port: 3306, proto: "tcp", service: "MySQL", description: "MySQL / MariaDB database.", risks: ["Database exposed", "Weak root password"], checks: ["Restrict access", "Check the version"] },
  { port: 3389, proto: "tcp", service: "RDP", description: "Windows Remote Desktop.", risks: ["Brute force and credential stuffing", "BlueKeep and other RDP vulnerabilities", "Missing Network Level Authentication"], checks: ["Require NLA and MFA", "Place behind a VPN or gateway", "Check the TLS certificate"] },
  { port: 5432, proto: "tcp", service: "PostgreSQL", description: "PostgreSQL database.", risks: ["Database exposed", "Trust authentication"], checks: ["Restrict access", "Review pg_hba.conf"] },
  { port: 5601, proto: "tcp", service: "Kibana", description: "Elastic dashboards.", risks: ["Unauthenticated access to logs and data"], checks: ["Require authentication"] },
  { port: 5900, proto: "tcp", service: "VNC", description: "Remote desktop.", risks: ["No or weak password", "Unencrypted sessions"], checks: ["Require strong authentication", "Tunnel through SSH or VPN"] },
  { port: 5985, proto: "tcp", service: "WinRM (HTTP)", description: "Windows remote management.", risks: ["Remote command execution with valid credentials", "HTTP transport"], checks: ["Restrict to management networks", "Prefer HTTPS (5986)"] },
  { port: 6379, proto: "tcp", service: "Redis", description: "In-memory data store.", risks: ["No authentication by default", "Remote code execution through configuration abuse"], checks: ["Require authentication (requirepass/ACL)", "Bind to internal interfaces"] },
  { port: 6443, proto: "tcp", service: "Kubernetes API", description: "Kubernetes API server.", risks: ["Anonymous access", "Exposed cluster control plane"], checks: ["Check anonymous auth", "Restrict network access"] },
  { port: 8080, proto: "tcp", service: "HTTP alternate", description: "Proxies, application servers (Tomcat, Jenkins).", risks: ["Admin consoles", "Default credentials", "Open proxy"], checks: ["Identify the application", "Look for admin consoles"] },
  { port: 8443, proto: "tcp", service: "HTTPS alternate", description: "Admin interfaces and application servers.", risks: ["Admin consoles", "Self-signed certificates"], checks: ["Run the TLS analyzer", "Identify the application"] },
  { port: 9200, proto: "tcp", service: "Elasticsearch", description: "Search engine REST API.", risks: ["Unauthenticated data access", "Data deletion"], checks: ["Require authentication", "Restrict network access"] },
  { port: 11211, proto: "tcp/udp", service: "Memcached", description: "In-memory cache.", risks: ["No authentication", "UDP amplification"], checks: ["Disable UDP", "Bind to internal interfaces"] },
  { port: 27017, proto: "tcp", service: "MongoDB", description: "MongoDB database.", risks: ["No authentication on old defaults", "Exposed data"], checks: ["Require authentication", "Restrict network access"] },
];

export function portInfo(port: number): PortInfo | undefined {
  return PORTS.find((p) => p.port === port);
}

/** Port number or service name search. */
export function searchPorts(query: string): PortInfo[] {
  const q = query.trim().toLowerCase();
  if (!q) return PORTS;
  const n = Number(q);
  if (Number.isInteger(n) && n > 0) return PORTS.filter((p) => p.port === n);
  return PORTS.filter((p) => p.service.toLowerCase().includes(q) || p.description.toLowerCase().includes(q));
}
