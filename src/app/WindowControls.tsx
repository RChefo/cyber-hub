// SPDX-License-Identifier: Apache-2.0
import { Button, Tooltip } from "@heroui/react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Copy, Minus, Square, X } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { notify } from "@/lib/actions";
import { runtimeAvailable } from "@/lib/ipc";
import { cn } from "@/lib/utils";

/**
 * Minimize / maximize-restore / close for the frameless window, using Tauri's window API
 * (works on Windows and Linux). The maximize/restore icon follows the real window
 * state: it is re-read on every resize event, so maximizing by double-clicking the top bar,
 * snapping or keyboard shortcuts are reflected too. The buttons are not drag regions.
 */
export function WindowControls() {
  const runtime = runtimeAvailable();
  const [maximized, setMaximized] = useState(false);

  useEffect(() => {
    if (!runtime) return;
    const win = getCurrentWindow();
    let disposed = false;
    let unlisten: (() => void) | undefined;
    const sync = () =>
      win
        .isMaximized()
        .then((m) => !disposed && setMaximized(m))
        .catch(() => undefined);
    sync();
    win
      .onResized(sync)
      .then((fn) => {
        if (disposed) fn();
        else unlisten = fn;
      })
      .catch(() => undefined);
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [runtime]);

  if (!runtime) return null;

  const run = (label: string, action: () => Promise<void>) => async () => {
    try {
      await action();
    } catch (e) {
      notify.error(`Could not ${label} the window`, e);
    }
  };

  const win = getCurrentWindow();
  return (
    <div className="-mr-5 ml-1 flex h-full items-stretch self-stretch" role="group" aria-label="Window controls">
      <Control label="Minimize" onPress={run("minimize", () => win.minimize())}>
        <Minus className="size-4" strokeWidth={1.75} />
      </Control>
      <Control label={maximized ? "Restore" : "Maximize"} onPress={run(maximized ? "restore" : "maximize", () => win.toggleMaximize())}>
        {maximized ? <Copy className="size-[13px] -scale-x-100" strokeWidth={1.75} /> : <Square className="size-[13px]" strokeWidth={1.75} />}
      </Control>
      <Control label="Close" danger onPress={run("close", () => win.close())}>
        <X className="size-4" strokeWidth={1.75} />
      </Control>
    </div>
  );
}

function Control({ label, onPress, danger, children }: { label: string; onPress: () => void; danger?: boolean; children: ReactNode }) {
  return (
    <Tooltip delay={600}>
      <Button
        isIconOnly
        variant="ghost"
        aria-label={label}
        onPress={onPress}
        className={cn(
          "h-full w-12 min-w-12 rounded-none text-muted transition-colors",
          "hover:bg-white/[0.06] hover:text-foreground data-[pressed=true]:bg-white/[0.1]",
          danger && "hover:bg-danger hover:text-white data-[pressed=true]:bg-danger-hover",
        )}
      >
        {children}
      </Button>
      <Tooltip.Content placement="bottom">{label}</Tooltip.Content>
    </Tooltip>
  );
}
