// SPDX-License-Identifier: Apache-2.0
import { listen } from "@tauri-apps/api/event";
import { useEffect } from "react";
import { toast } from "@heroui/react";
import { invalidate } from "@/lib/query";
import { useApp } from "./store";

/**
 * One dismissable notification per new version, raised by the backend after an update check.
 * It never opens a dialog and never starts a download.
 */
export function UpdateNotices() {
  const { runtime, navigate } = useApp();
  useEffect(() => {
    if (!runtime) return;
    let un: (() => void) | undefined;
    let disposed = false;
    listen<{ version: string }>("update-notice", (e) => {
      invalidate("activity");
      toast.info(`ExploitX ${e.payload.version} is available`, {
        description: "Review the release notes and install it from Settings → Updates.",
        timeout: 10000,
        actionProps: { children: "View", variant: "tertiary", size: "sm", onPress: () => navigate("settings") },
      });
    })
      .then((fn) => (disposed ? fn() : (un = fn)))
      .catch(() => undefined);
    return () => {
      disposed = true;
      un?.();
    };
  }, [runtime, navigate]);
  return null;
}
