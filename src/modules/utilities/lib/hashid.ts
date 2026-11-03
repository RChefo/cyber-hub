/** Heuristic hash identification by prefix, length and alphabet. Suggestions, not proof. */

export interface HashCandidate {
  name: string;
  /** hashcat mode where well known */
  hashcat?: number;
  /** John the Ripper format name where well known */
  john?: string;
  confidence: "high" | "medium" | "low";
  note?: string;
}

const HEX = /^[0-9a-f]+$/i;

export function identifyHash(raw: string): HashCandidate[] {
  const h = raw.trim();
  if (!h) return [];
  const out: HashCandidate[] = [];
  const add = (c: HashCandidate) => out.push(c);

  // Modular crypt / prefixed formats — high confidence
  if (/^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(h)) add({ name: "bcrypt", hashcat: 3200, john: "bcrypt", confidence: "high" });
  if (/^\$6\$/.test(h)) add({ name: "sha512crypt (Unix $6$)", hashcat: 1800, john: "sha512crypt", confidence: "high" });
  if (/^\$5\$/.test(h)) add({ name: "sha256crypt (Unix $5$)", hashcat: 7400, john: "sha256crypt", confidence: "high" });
  if (/^\$1\$/.test(h)) add({ name: "md5crypt (Unix $1$)", hashcat: 500, john: "md5crypt", confidence: "high" });
  if (/^\$apr1\$/.test(h)) add({ name: "Apache apr1 MD5", hashcat: 1600, confidence: "high" });
  if (/^\$y\$/.test(h)) add({ name: "yescrypt", confidence: "high", note: "Default on recent Debian/Ubuntu/Fedora" });
  if (/^\$argon2(id|i|d)\$/.test(h)) add({ name: `Argon2 (${h.slice(1, h.indexOf("$", 1))})`, confidence: "high" });
  if (/^\$pbkdf2(-sha\d+)?\$/.test(h)) add({ name: "PBKDF2 (passlib format)", confidence: "high" });
  if (/^pbkdf2_sha256\$\d+\$/.test(h)) add({ name: "Django PBKDF2-SHA256", hashcat: 10000, confidence: "high" });
  if (/^sha1\$\w+\$[0-9a-f]{40}$/i.test(h)) add({ name: "Django SHA-1", hashcat: 124, confidence: "high" });
  if (/^\$P\$|^\$H\$/.test(h)) add({ name: "phpass (WordPress / phpBB3)", hashcat: 400, john: "phpass", confidence: "high" });
  if (/^\*[0-9A-F]{40}$/i.test(h)) add({ name: "MySQL 4.1 / 5.x", hashcat: 300, john: "mysql-sha1", confidence: "high" });
  if (/^\{SSHA\}/i.test(h)) add({ name: "LDAP SSHA (salted SHA-1)", hashcat: 111, confidence: "high" });
  if (/^\{SHA\}/i.test(h)) add({ name: "LDAP SHA-1 (base64)", hashcat: 101, confidence: "high" });
  if (/^0x0100[0-9a-f]{48}$/i.test(h)) add({ name: "MSSQL 2005", hashcat: 132, confidence: "high" });
  if (/^0x0200[0-9a-f]{136}$/i.test(h)) add({ name: "MSSQL 2012+", hashcat: 1731, confidence: "high" });
  if (/^[^:]+:\d+:[0-9a-f]{32}:[0-9a-f]{32}:::$/i.test(h)) add({ name: "Windows pwdump (LM:NTLM)", hashcat: 1000, confidence: "high", note: "Audit the NTLM part with mode 1000" });
  if (/^\$krb5tgs\$/.test(h)) add({ name: "Kerberos 5 TGS-REP", hashcat: 13100, confidence: "high" });
  if (/^\$krb5asrep\$/.test(h)) add({ name: "Kerberos 5 AS-REP", hashcat: 18200, confidence: "high" });
  if (/^[^:]+::[^:]+:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$/i.test(h)) add({ name: "NetNTLMv2", hashcat: 5600, confidence: "high" });
  if (out.length) return out;

  // Raw hex digests — ambiguous by nature
  if (HEX.test(h)) {
    switch (h.length) {
      case 8:
        add({ name: "CRC32", hashcat: 11500, confidence: "medium" });
        add({ name: "Adler-32", confidence: "low" });
        break;
      case 16:
        add({ name: "MySQL 3.2.3 (OLD_PASSWORD)", hashcat: 200, confidence: "medium" });
        add({ name: "Half MD5", confidence: "low" });
        add({ name: "CRC64", confidence: "low" });
        break;
      case 32:
        add({ name: "MD5", hashcat: 0, john: "raw-md5", confidence: "high" });
        add({ name: "NTLM", hashcat: 1000, john: "nt", confidence: "high", note: "Same length as MD5 — context decides (Windows dumps are NTLM)" });
        add({ name: "MD4", hashcat: 900, confidence: "medium" });
        add({ name: "LM", hashcat: 3000, john: "lm", confidence: "low", note: "Usually uppercase; second half often aad3b435b51404ee" });
        break;
      case 40:
        add({ name: "SHA-1", hashcat: 100, john: "raw-sha1", confidence: "high" });
        add({ name: "RIPEMD-160", hashcat: 6000, confidence: "medium" });
        add({ name: "MySQL 5 without leading *", hashcat: 300, confidence: "low" });
        break;
      case 56:
        add({ name: "SHA-224", hashcat: 1300, confidence: "high" });
        add({ name: "SHA3-224", hashcat: 17300, confidence: "low" });
        break;
      case 64:
        add({ name: "SHA-256", hashcat: 1400, john: "raw-sha256", confidence: "high" });
        add({ name: "SHA3-256", hashcat: 17400, confidence: "medium" });
        add({ name: "Keccak-256", hashcat: 17800, confidence: "low" });
        add({ name: "BLAKE2s-256", confidence: "low" });
        break;
      case 96:
        add({ name: "SHA-384", hashcat: 10800, confidence: "high" });
        add({ name: "SHA3-384", hashcat: 17500, confidence: "low" });
        break;
      case 128:
        add({ name: "SHA-512", hashcat: 1700, john: "raw-sha512", confidence: "high" });
        add({ name: "SHA3-512", hashcat: 17600, confidence: "medium" });
        add({ name: "Whirlpool", hashcat: 6100, confidence: "medium" });
        add({ name: "BLAKE2b-512", hashcat: 600, confidence: "low" });
        break;
    }
    if (h.length === 32 && /^[0-9A-F]+$/.test(h) && /AAD3B435B51404EE/i.test(h)) {
      const lm = out.find((c) => c.name === "LM");
      if (lm) lm.confidence = "high";
    }
    if (out.length) return out;
  }

  if (/^[A-Za-z0-9+/]+={0,2}$/.test(h) && h.length % 4 === 0) {
    const bytes = (h.length / 4) * 3 - (h.endsWith("==") ? 2 : h.endsWith("=") ? 1 : 0);
    const map: Record<number, string> = { 16: "MD5", 20: "SHA-1", 32: "SHA-256", 48: "SHA-384", 64: "SHA-512" };
    if (map[bytes]) add({ name: `Base64-encoded ${map[bytes]} digest`, confidence: "medium", note: `${bytes} raw bytes` });
    else add({ name: "Base64 data (not a recognized digest length)", confidence: "low", note: `${bytes} raw bytes` });
  }
  return out;
}
