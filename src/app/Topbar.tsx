// SPDX-License-Identifier: Apache-2.0
import { Button, Dropdown, Label, Popover, Tooltip } from "@heroui/react";
import { Activity as ActivityIcon, Bell, ChevronDown, Search, Settings, SquareTerminal, UserRound } from "lucide-react";
import { Kbd } from "@/components/ui/Code";
import { ActivityIcon as KindIcon } from "@/modules/dashboard/activityMeta";
import { openTerminal } from "@/lib/actions";
import { dragRegion } from "@/lib/dragRegion";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import { formatRelative, modKey } from "@/lib/utils";
import { navItem } from "./routes";
import { useApp } from "./store";
import { WindowControls } from "./WindowControls";

function RunningIndicator() {
  const { runtime, navigate } = useApp();
  const runs = useQuery(["executions"], () => api.execList(20), [], runtime);
  const running = (runs.data ?? []).filter((r) => r.running).length;
  if (!running) return null;
  return (
    <Button size="sm" variant="tertiary" onPress={() => navigate("runs")} className="gap-2">
      <span className="relative flex size-2">
        <span className="absolute inline-flex size-full animate-ping rounded-full bg-accent opacity-60" />
        <span className="relative inline-flex size-2 rounded-full bg-accent" />
      </span>
      {running} running
    </Button>
  );
}

function Notifications() {
  const { runtime, navigate, prefs, setPref } = useApp();
  const activity = useQuery(["activity"], () => api.activityList(12), [], runtime);
  const lastSeen = typeof prefs["notifications.lastSeen"] === "string" ? (prefs["notifications.lastSeen"] as string) : null;
  const items = activity.data ?? [];
  const unseen = lastSeen ? items.filter((a) => a.createdAt > lastSeen).length : items.length;

  return (
    <Popover onOpenChange={(open) => !open && items[0] && setPref("notifications.lastSeen", items[0].createdAt)}>
      <Button isIconOnly variant="ghost" size="sm" aria-label={`Notifications${unseen ? `, ${unseen} new` : ""}`} className="relative">
        <Bell className="size-[17px]" strokeWidth={1.75} />
        {unseen > 0 && <span className="absolute top-1.5 right-1.5 size-1.5 rounded-full bg-accent" />}
      </Button>
      <Popover.Content placement="bottom end" className="w-[360px] bg-overlay p-0">
        <Popover.Dialog className="p-0 outline-none">
          <div className="flex items-center justify-between px-4 pt-3 pb-2">
            <div className="text-[14px] font-medium">Recent activity</div>
            <span className="text-[12px] text-muted">Local only</span>
          </div>
          <div className="scroll-area max-h-[360px] py-1">
            {items.length === 0 && <div className="px-4 py-6 text-center text-[13px] text-muted">{activity.error ?? "Nothing has happened yet."}</div>}
            {items.map((a) => (
              <div key={a.id} className="flex items-start gap-3 px-4 py-2">
                <KindIcon kind={a.kind} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] text-foreground">{a.title}</div>
                  {a.detail && <div className="truncate text-[12px] text-muted">{a.detail}</div>}
                </div>
                <div className="shrink-0 text-[11.5px] text-muted">{formatRelative(a.createdAt)}</div>
              </div>
            ))}
          </div>
          <div className="p-1.5">
            <Button fullWidth size="sm" variant="ghost" onPress={() => navigate("dashboard")}>
              <ActivityIcon className="size-3.5" />
              View dashboard activity
            </Button>
          </div>
        </Popover.Dialog>
      </Popover.Content>
    </Popover>
  );
}

export function Topbar() {
  const { route, setPaletteOpen, navigate, system } = useApp();
  const item = navItem(route.page);

  return (
    // the window is frameless, so empty top-bar space moves the window (double-click toggles
    // maximize). Interactive children are unaffected.
    <header {...dragRegion()} className="flex h-14 shrink-0 items-center gap-3 bg-background px-5">
      <div {...dragRegion()} className="min-w-0 flex-1">
        <div {...dragRegion()} className="truncate text-[14.5px] font-medium">{item.label}</div>
      </div>

      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        className="flex h-8 w-[min(380px,36vw)] items-center gap-2 rounded-lg bg-field px-2.5 text-left text-[13px] text-muted outline-none transition-colors hover:bg-surface-tertiary focus-visible:ring-2 focus-visible:ring-focus"
        aria-label="Open global search"
      >
        <Search className="size-[15px]" strokeWidth={1.75} />
        <span className="flex-1 truncate">Search tools, commands, projects…</span>
        <Kbd>{modKey}</Kbd>
        <Kbd>K</Kbd>
      </button>

      <div className="flex items-center gap-1">
        <RunningIndicator />
        <Tooltip delay={400}>
          <Button isIconOnly variant="ghost" size="sm" aria-label="Open system terminal" onPress={() => openTerminal()}>
            <SquareTerminal className="size-[17px]" strokeWidth={1.75} />
          </Button>
          <Tooltip.Content>Open system terminal</Tooltip.Content>
        </Tooltip>
        <Notifications />
        <Dropdown>
          <Button variant="ghost" size="sm" className="gap-1.5 pr-1.5 pl-1" aria-label="User preferences">
            <span className="flex size-6 items-center justify-center rounded-full bg-default text-muted">
              <UserRound className="size-3.5" />
            </span>
            <ChevronDown className="size-3.5 text-muted" />
          </Button>
          <Dropdown.Popover placement="bottom end" className="min-w-[220px]">
            <div className="px-3 pt-2.5 pb-1.5">
              <Label className="text-[13px] font-medium text-foreground">{system?.hostname || "Local workstation"}</Label>
              <div className="text-[12px] text-muted">
                {system ? `${system.osName} ${system.osVersion}` : "Desktop runtime not connected"}
              </div>
            </div>
            <Dropdown.Menu
              aria-label="User menu"
              onAction={(key) => {
                if (key === "settings") navigate("settings");
                if (key === "runs") navigate("runs");
                if (key === "terminal") openTerminal();
              }}
            >
              <Dropdown.Item id="settings" textValue="Preferences">
                <Settings className="size-4 text-muted" />
                Preferences
              </Dropdown.Item>
              <Dropdown.Item id="runs" textValue="Execution history">
                <ActivityIcon className="size-4 text-muted" />
                Execution history
              </Dropdown.Item>
              <Dropdown.Item id="terminal" textValue="Open terminal">
                <SquareTerminal className="size-4 text-muted" />
                Open terminal
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
      </div>
      <WindowControls />
    </header>
  );
}
