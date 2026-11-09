import { Container } from "lucide-react";
import { api } from "@/lib/ipc";
import { KIND_LABEL, containerFinding } from "../lib/containers";
import { type ConfigCheckConfig, ConfigCheckTool } from "./ConfigCheckTool";

const CONTAINER_CHECKS: ConfigCheckConfig = {
  privacy: "Reads the text, file or folder on this device; nothing is contacted, built or run. Checks follow the Kubernetes Pod Security Standards (baseline and restricted), the CIS Docker Benchmark and the Kubernetes RBAC good practices.",
  kinds: [
    { id: "auto", label: "Detect" },
    { id: "dockerfile", label: "Dockerfile" },
    { id: "compose", label: "Compose file" },
    { id: "kubernetes", label: "Kubernetes manifests" },
  ],
  kindLabel: KIND_LABEL,
  placeholder: 'FROM node:20-alpine\nCOPY . /app\nCMD ["node", "/app/server.js"]',
  folderHint: "A folder is searched for Dockerfiles, Compose files and manifests; .git, node_modules, vendor and build folders are skipped.",
  empty: { icon: Container, title: "No container configuration found", description: "No Dockerfile, Compose file or Kubernetes manifest was found." },
  scanText: (text, kind) => api.containerScanText(text, kind),
  scanPick: (folder) => api.containerScanPick(folder),
  finding: containerFinding,
};

/** Security utility: Dockerfile, Compose and Kubernetes manifest checks, offline. */
export function ContainerTool() {
  return <ConfigCheckTool config={CONTAINER_CHECKS} />;
}
