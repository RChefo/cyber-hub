// SPDX-License-Identifier: Apache-2.0
import { useEffect } from "react";
import { toast } from "@heroui/react";
import { api } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import { restoreNotice } from "@/modules/settings/restore";
import { useApp } from "./store";

/** One notice with the result of a restore applied when ExploitX started (restore.rs). */
export function RestoreNotice() {
  const { runtime } = useApp();
  useEffect(() => {
    if (!runtime) return;
    api
      .databaseRestoreOutcome()
      .then((o) => {
        if (!o) return;
        invalidate("activity");
        const n = restoreNotice(o);
        toast[n.tone](n.title, { description: n.description, timeout: 15000 });
      })
      .catch(() => undefined);
  }, [runtime]);
  return null;
}
