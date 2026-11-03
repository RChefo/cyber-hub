import { Button, Tooltip } from "@heroui/react";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { cn } from "@/lib/utils";
import { NAV_GROUPS, SETTINGS_ITEM, type NavItem } from "./routes";
import { useApp } from "./store";

function NavLink({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  const { route, navigate } = useApp();
  const active = route.page === item.id;
  const Icon = item.icon;
  const button = (
    <Button
      variant="ghost"
      onPress={() => navigate(item.id)}
      aria-current={active ? "page" : undefined}
      aria-label={collapsed ? item.label : undefined}
      className={cn(
        "group relative h-8 w-full justify-start gap-2.5 rounded-md px-2.5 text-[13.5px] font-normal",
        active ? "bg-white/[0.06] text-foreground hover:bg-white/[0.07]" : "text-muted hover:bg-white/[0.035] hover:text-foreground",
        collapsed && "justify-center px-0",
      )}
    >
      {active && <span className="absolute top-1.5 bottom-1.5 left-0 w-[2px] rounded-full bg-accent" aria-hidden />}
      <Icon className={cn("size-[17px] shrink-0", active ? "text-accent-soft-foreground" : "text-muted group-hover:text-foreground")} strokeWidth={1.75} />
      {!collapsed && <span className="truncate">{item.label}</span>}
    </Button>
  );
  if (!collapsed) return button;
  return (
    <Tooltip delay={200}>
      {button}
      <Tooltip.Content placement="right">{item.label}</Tooltip.Content>
    </Tooltip>
  );
}

export function Sidebar() {
  const { prefs, setPref } = useApp();
  const collapsed = prefs["ui.sidebarCollapsed"] === true;

  return (
    <aside
      className={cn(
        "flex h-full shrink-0 flex-col bg-background-secondary transition-[width] duration-200",
        collapsed ? "w-[60px]" : "w-[232px]",
      )}
      aria-label="Primary navigation"
    >
      <div data-tauri-drag-region className={cn("flex h-14 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        <img src="/logo.svg" alt="" className="size-7 rounded-[7px]" />
        {!collapsed && (
          <div className="leading-tight">
            <div className="text-[14.5px] font-semibold tracking-tight">Cyber Hub</div>
            <div className="text-[11.5px] text-muted">Security workstation</div>
          </div>
        )}
      </div>

      <nav className="scroll-area flex-1 px-2.5 pt-2 pb-3">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="mb-4">
            {!collapsed ? (
              <div className="mb-1 px-2.5 text-[11.5px] font-medium text-muted/80">{group.label}</div>
            ) : (
              <div className="mb-2 h-1" aria-hidden />
            )}
            <div className="flex flex-col gap-0.5">
              {group.items.map((item) => (
                <NavLink key={item.id} item={item} collapsed={collapsed} />
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="flex flex-col gap-0.5 px-2.5 pt-1 pb-3">
        <NavLink item={SETTINGS_ITEM} collapsed={collapsed} />
        <Button
          variant="ghost"
          size="sm"
          className={cn("h-8 justify-start gap-2.5 px-2.5 text-[13px] font-normal text-muted", collapsed && "justify-center px-0")}
          onPress={() => setPref("ui.sidebarCollapsed", !collapsed)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <PanelLeftOpen className="size-[17px]" strokeWidth={1.75} /> : <PanelLeftClose className="size-[17px]" strokeWidth={1.75} />}
          {!collapsed && "Collapse"}
        </Button>
      </div>
    </aside>
  );
}
