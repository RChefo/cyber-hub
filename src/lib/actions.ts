import { toast } from "@heroui/react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { api, errorMessage, IpcError, runtimeAvailable } from "./ipc";
import { invalidate } from "./query";

export const notify = {
  success: (title: string, description?: string) => toast.success(title, description ? { description } : undefined),
  info: (title: string, description?: string) => toast.info(title, description ? { description } : undefined),
  warning: (title: string, description?: string) => toast.warning(title, description ? { description } : undefined),
  /** A declined native confirmation (`cancelled`) is the analyst's decision, not a failure: it is
   * shown as information, with the backend's message saying what did not happen. */
  error: (title: string, error?: unknown) =>
    error instanceof IpcError && error.kind === "cancelled"
      ? toast.info(error.message)
      : toast.danger(title, error !== undefined ? { description: errorMessage(error) } : undefined),
};

/** Copy text to the clipboard. Never executes anything. */
export async function copyText(text: string, label = "Copied to clipboard"): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    notify.success(label);
    return true;
  } catch (e) {
    notify.error("Could not copy to clipboard", e);
    return false;
  }
}

/** Copy a command and record it in command history. */
export async function copyCommand(command: string, source: string, toolId?: string | null, projectId?: number | null) {
  const ok = await copyText(command, "Command copied");
  if (ok && runtimeAvailable()) {
    api
      .commandHistoryAdd(command, source, toolId, projectId)
      .then(() => invalidate("history", "activity"))
      .catch(() => undefined);
  }
}

/** Open an http(s) URL in the system browser (Tauri opener plugin, scoped to http/https). */
export async function openExternal(url: string): Promise<void> {
  if (!/^https?:\/\//i.test(url)) {
    notify.error("Only http and https links can be opened");
    return;
  }
  try {
    if (runtimeAvailable()) await openUrl(url);
    else window.open(url, "_blank", "noopener,noreferrer");
  } catch (e) {
    notify.error("Could not open the link", e);
  }
}

/** Open a catalog/custom resource and record the visit. */
export async function openResource(key: string, title: string, url: string) {
  await openExternal(url);
  if (runtimeAvailable()) {
    api
      .resourceVisit(key, title, url)
      .then(() => invalidate("resources", "activity"))
      .catch(() => undefined);
  }
}

/** Open a terminal in the home folder (the backend takes no directory from the page). */
export async function openTerminal() {
  try {
    const name = await api.openTerminal();
    notify.info(`Opened ${name}`);
  } catch (e) {
    notify.error("Could not open a terminal", e);
  }
}

/** Copy the command, then open a terminal so the user can paste and review it before pressing Enter. */
export async function copyAndOpenTerminal(command: string, source: string, toolId?: string | null) {
  await copyCommand(command, source, toolId);
  try {
    const name = await api.openTerminal();
    notify.info(`Opened ${name}`, "The command is on your clipboard — paste it, review it, then press Enter.");
  } catch (e) {
    notify.error("Could not open a terminal", e);
  }
}
