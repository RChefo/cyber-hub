// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { LINUX_DIRS, LINUX_PATHS, MIN_SIZE, REQUIRED, noticesProblems, packageProblems, parse7zSlt, parseDpkgList, parseMsiFiles, parseRpmDump } from "./check-package-notices.mjs";

// Mission 14: the release checks that every package carries THIRD_PARTY_LICENSES.txt. The listings
// below are real output of the tools on the debug packages built from this tree (2026-11-13).
const DEB = `-rwxr-xr-x 0/0       657956992 2026-11-13 15:03 usr/bin/cyber-hub
-rwxr-xr-x 0/0         1087996 2026-11-13 15:03 usr/lib/Cyber Hub/THIRD_PARTY_LICENSES.txt
-rwxr-xr-x 0/0         1087996 2026-11-13 15:03 usr/share/doc/cyber-hub/THIRD_PARTY_LICENSES.txt
lrwxrwxrwx root/root         0 2026-11-13 15:03 ./usr/lib/libfoo.so -> libfoo.so.1
`;
const RPM = `/usr/bin/cyber-hub 657956992 1794582208 2637d2f22c2587705434d9ecd28cfa9df4383e52b6096fba4c3147f6e9d99b9c 0100755 root root 0 0 0 X
/usr/lib/Cyber Hub/THIRD_PARTY_LICENSES.txt 1087996 1794579600 34a867f382ed13bbd54dbb155c2bd5be1cf7907e1a749666080af23ae5455fe4 0100777 root root 0 0 0 X
/usr/share/licenses/cyber-hub/THIRD_PARTY_LICENSES.txt 1087996 1794579600 34a867f382ed13bbd54dbb155c2bd5be1cf7907e1a749666080af23ae5455fe4 0100777 root root 0 0 0 X
`;
const NSIS = `
Listing archive: /w/setup.exe

--
Path = /w/setup.exe
Type = Nsis
Method = LZMA:23
Solid = +
Offset = 111514

----------
Path = $PLUGINSDIR/System.dll
Size = 12288
Packed Size =

Path = THIRD_PARTY_LICENSES.txt
Size = 1087996
Packed Size =
Modified = 2026-11-13 14:20:00.0000000
Attributes = A
`;
const MSI = "cyber-hub.exe\t79329280\r\ncyberhub-mcp.exe\t10821632\r\nTHIRD_~1.TXT|THIRD_PARTY_LICENSES.txt\t1087996\r\n";

describe("package listings", () => {
  it("reads dpkg-deb listings as absolute paths, with or without ./", () => {
    const e = parseDpkgList(DEB);
    expect(e).toContainEqual({ path: LINUX_PATHS.deb, size: 1087996 });
    expect(e).toContainEqual({ path: "/usr/lib/Cyber Hub/THIRD_PARTY_LICENSES.txt", size: 1087996 });
    expect(e).toContainEqual({ path: "/usr/lib/libfoo.so", size: 0 });
  });

  it("reads rpm --dump listings, paths with spaces included", () => {
    const e = parseRpmDump(RPM);
    expect(e).toHaveLength(3);
    expect(e[1]).toEqual({ path: "/usr/lib/Cyber Hub/THIRD_PARTY_LICENSES.txt", size: 1087996 });
    expect(e).toContainEqual({ path: LINUX_PATHS.rpm, size: 1087996 });
  });

  it("reads 7-Zip technical listings of the NSIS installer", () => {
    const e = parse7zSlt(NSIS);
    expect(e).toContainEqual({ path: "THIRD_PARTY_LICENSES.txt", size: 1087996 });
    expect(e).toContainEqual({ path: "$PLUGINSDIR/System.dll", size: 12288 });
  });

  it("reads the MSI File table, short|long names included", () => {
    expect(parseMsiFiles(MSI)).toEqual([
      { path: "cyber-hub.exe", size: 79329280 },
      { path: "cyberhub-mcp.exe", size: 10821632 },
      { path: "THIRD_PARTY_LICENSES.txt", size: 1087996 },
    ]);
  });
});

describe("notices in a package", () => {
  it("passes when the full notices are at the required place", () => {
    expect(noticesProblems("x.deb", parseDpkgList(DEB), LINUX_PATHS.deb)).toEqual([]);
    expect(noticesProblems("x.rpm", parseRpmDump(RPM), LINUX_PATHS.rpm)).toEqual([]);
    expect(noticesProblems("setup.exe", parse7zSlt(NSIS))).toEqual([]);
    expect(noticesProblems("x.msi", parseMsiFiles(MSI))).toEqual([]);
  });

  it("fails when they are missing, elsewhere, or cut short", () => {
    expect(noticesProblems("old.msi", [{ path: "cyber-hub.exe", size: 21524992 }])).toEqual(["old.msi does not contain THIRD_PARTY_LICENSES.txt"]);
    // the resource alone is not enough for the deb: Debian's place for license files is required
    const onlyResource = parseDpkgList(DEB).filter((e) => !e.path.startsWith("/usr/share/doc/"));
    expect(noticesProblems("x.deb", onlyResource, LINUX_PATHS.deb)).toHaveLength(1);
    expect(noticesProblems("x.msi", [{ path: "THIRD_PARTY_LICENSES.txt", size: MIN_SIZE - 1 }])[0]).toMatch(/not the full notices/);
  });
});

// Mission 15: every package also carries ExploitX's own LICENSE (Apache-2.0) and NOTICE.
describe("license files in a package", () => {
  const withLicense = (entries, dir = "") => [...entries, { path: `${dir}LICENSE`, size: 11358 }, { path: `${dir}NOTICE`, size: 1066 }];

  it("requires LICENSE, NOTICE and the notices, in the deb's and rpm's license folders", () => {
    expect(packageProblems("x.deb", withLicense(parseDpkgList(DEB), LINUX_DIRS.deb), LINUX_DIRS.deb)).toEqual([]);
    expect(packageProblems("x.rpm", withLicense(parseRpmDump(RPM), LINUX_DIRS.rpm), LINUX_DIRS.rpm)).toEqual([]);
    expect(packageProblems("setup.exe", withLicense(parse7zSlt(NSIS)))).toEqual([]);
    expect(packageProblems("x.msi", withLicense(parseMsiFiles(MSI)))).toEqual([]);
  });

  it("names each missing or truncated file", () => {
    expect(packageProblems("x.msi", parseMsiFiles(MSI))).toEqual(["x.msi does not contain LICENSE", "x.msi does not contain NOTICE"]);
    expect(packageProblems("x.deb", withLicense(parseDpkgList(DEB), "/usr/lib/Cyber Hub/"), LINUX_DIRS.deb)).toEqual([
      "x.deb does not contain /usr/share/doc/cyber-hub/LICENSE",
      "x.deb does not contain /usr/share/doc/cyber-hub/NOTICE",
    ]);
    const short = [...parseMsiFiles(MSI), { path: "LICENSE", size: 1000 }, { path: "NOTICE", size: 1066 }];
    expect(packageProblems("x.msi", short)).toEqual(["x.msi: LICENSE is 1000 bytes, too small to be the full text"]);
    expect(REQUIRED.map((r) => r.name)).toEqual(["THIRD_PARTY_LICENSES.txt", "LICENSE", "NOTICE"]);
  });
});
