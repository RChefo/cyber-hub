import { Button, Tooltip } from "@heroui/react";
import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import { dragRegion } from "@/lib/dragRegion";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { sidebarCollapsed, useNarrowWindow } from "@/lib/viewport";
import { NavTree } from "@/components/ui/NavTree";
import { BrandSymbol, Logo } from "@/components/brand/Logo";
import { NAV_GROUPS, SETTINGS_ITEM, type NavItem, type PageId } from "./routes";
import { useApp } from "./store";

function NavLink({ item, collapsed, badge }: { item: NavItem; collapsed: boolean; badge?: number }) {
  const { route, navigate } = useApp();
  const active = route.page === item.id;
  const Icon = item.icon;
  const button = (
    <Button
      variant="ghost"
      onPress={() => navigate(item.id)}
      aria-current={active ? "page" : undefined}
      aria-label={collapsed ? (badge ? `${item.label}, ${badge} waiting` : item.label) : badge ? `${item.label}, ${badge} waiting for approval` : undefined}
      className={cn(
        "group relative h-8 w-full justify-start gap-2.5 rounded-md px-2.5 text-[13.5px] font-normal",
        active ? "bg-white/[0.06] text-foreground hover:bg-white/[0.07]" : "text-muted hover:bg-white/[0.035] hover:text-foreground",
        collapsed && "justify-center px-0",
      )}
    >
      {active && <span className="absolute top-1.5 bottom-1.5 left-0 w-[2px] rounded-full bg-accent" aria-hidden />}
      <Icon className={cn("size-[17px] shrink-0", active ? "text-accent-soft-foreground" : "text-muted group-hover:text-foreground")} strokeWidth={1.75} />
      {!collapsed && <span className="truncate">{item.label}</span>}
      {badge ? (
        collapsed ? (
          <span className="absolute top-1 right-2 size-1.5 rounded-full bg-warning" aria-hidden />
        ) : (
          <span className="tabular ml-auto rounded-full bg-warning-soft px-1.5 text-[11px] leading-[18px] text-warning-soft-foreground" aria-hidden>
            {badge}
          </span>
        )
      ) : null}
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
  const { prefs, setPref, runtime, route, navigate } = useApp();
  // icons only when the user chose it, or when the window is too narrow for labels (scaled screens)
  const narrow = useNarrowWindow();
  const preferCollapsed = prefs["ui.sidebarCollapsed"] === true;
  const collapsed = sidebarCollapsed(narrow ? 0 : Number.POSITIVE_INFINITY, preferCollapsed);
  // MCP requests waiting for approval (refreshed whenever the approval listener sees a change)
  const mcpPending = useQuery(["mcp"], api.mcpPending, [], runtime).data?.length ?? 0;

  return (
    <aside
      className={cn(
        "flex h-full shrink-0 flex-col bg-background-secondary transition-[width] duration-200",
        collapsed ? "w-[60px]" : "w-[244px]",
      )}
      aria-label="Primary navigation"
    >
      <div {...dragRegion()} className={cn("flex h-14 items-center gap-2.5 px-4", collapsed && "justify-center px-0")}>
        {collapsed ? (
          <BrandSymbol height={22} label="ExploitX" className="text-bone" />
        ) : (
          <div className="flex flex-col gap-[5px]">
            <Logo capHeight={12.5} className="text-bone" />
            <div className="text-[11px] tracking-[0.01em] text-muted">Security research platform</div>
          </div>
        )}
      </div>

      {collapsed ? (
        <nav className="scroll-area flex-1 px-2.5 pt-2 pb-3">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} className="mb-4">
              <div className="mb-2 h-1" aria-hidden />
              <div className="flex flex-col gap-0.5">
                {group.items.map((item) => (
                  <NavLink key={item.id} item={item} collapsed badge={item.id === "mcp" ? mcpPending : undefined} />
                ))}
              </div>
            </div>
          ))}
        </nav>
      ) : (
        // expanded: the groups as a tree (NavTree); every group starts open
        <div className="scroll-area flex-1 px-3 pt-1 pb-3">
          <NavTree
            aria-label="Sections"
            groups={NAV_GROUPS.map((group) => ({
              label: group.label,
              children: group.items.map((item) => ({
                value: item.id,
                icon: item.icon,
                ...(item.id === "mcp" && mcpPending
                  ? {
                      ariaLabel: `${item.label}, ${mcpPending} waiting for approval`,
                      label: (
                        <span className="flex items-center gap-2">
                          {item.label}
                          <span className="tabular rounded-full bg-warning-soft px-1.5 text-[11px] leading-[18px] text-warning-soft-foreground" aria-hidden>
                            {mcpPending}
                          </span>
                        </span>
                      ),
                    }
                  : { label: item.label }),
              })),
            }))}
            value={route.page}
            onSelect={(id) => navigate(id as PageId)}
          />
        </div>
      )}

      <div className="flex flex-col gap-0.5 px-2.5 pt-1 pb-3">
        <NavLink item={SETTINGS_ITEM} collapsed={collapsed} />
        {/* a narrow window keeps icons only, so there is nothing to expand */}
        {!narrow && (
          <Button
            variant="ghost"
            size="sm"
            className={cn("h-8 justify-start gap-2.5 px-2.5 text-[13px] font-normal text-muted", collapsed && "justify-center px-0")}
            onPress={() => setPref("ui.sidebarCollapsed", !preferCollapsed)}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <PanelLeftOpen className="size-[17px]" strokeWidth={1.75} /> : <PanelLeftClose className="size-[17px]" strokeWidth={1.75} />}
            {!collapsed && "Collapse"}
          </Button>
        )}
      </div>
    </aside>
  );
}
