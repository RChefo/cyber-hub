// SPDX-License-Identifier: Apache-2.0
import { ChevronDown } from "lucide-react";
import { type ComponentType, type KeyboardEvent, type ReactNode, useId, useRef, useState } from "react";
import { initialOpen, nextFocus } from "@/lib/navTree";
import { cn } from "@/lib/utils";
import "./NavTree.css";

export interface NavTreeItem {
  value: string;
  label: ReactNode;
  icon?: ComponentType<{ className?: string; strokeWidth?: number }>;
  /** accessible name when `label` is not plain text (for example a label with a badge) */
  ariaLabel?: string;
}

export interface NavTreeGroup {
  label: string;
  children: NavTreeItem[];
}

/**
 * The sidebar's grouped navigation (Mission 14; original code that replaces the React Bits BranchedMenu).
 *
 * * Groups are disclosure buttons (`aria-expanded`); items are buttons with `aria-current="page"` when active.
 * * A trunk and a rounded elbow per item connect the items to their group (CSS, NavTree.css); the active
 *   item's elbow and its group's marker use the accent colour.
 * * Arrow keys, Home and End move between the visible rows; Tab works as usual.
 * * Folding animates row heights and is instant with `prefers-reduced-motion`.
 */
export function NavTree({
  groups,
  value,
  onSelect,
  openGroups,
  className,
  "aria-label": ariaLabel,
}: {
  groups: NavTreeGroup[];
  value?: string;
  onSelect: (value: string) => void;
  /** groups open at first; default: all */
  openGroups?: number[];
  className?: string;
  "aria-label"?: string;
}) {
  const [open, setOpen] = useState(() => initialOpen(groups, value, openGroups));
  const id = useId();
  const root = useRef<HTMLElement>(null);

  const toggle = (i: number) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });

  const onKeyDown = (e: KeyboardEvent<HTMLElement>) => {
    const rows = [...(root.current?.querySelectorAll<HTMLButtonElement>("[data-nav-row]:not([data-hidden])") ?? [])];
    const target = nextFocus(rows.indexOf(document.activeElement as HTMLButtonElement), rows.length, e.key);
    if (target === null) return;
    e.preventDefault();
    rows[target]?.focus();
  };

  return (
    <nav ref={root} aria-label={ariaLabel} className={cn("navtree", className)} onKeyDown={onKeyDown}>
      {groups.map((group, gi) => {
        const isOpen = open.has(gi);
        const holdsActive = group.children.some((c) => c.value === value);
        const listId = `${id}-g${gi}`;
        return (
          <div key={group.label} className="navtree-group" data-active={holdsActive || undefined}>
            <button
              type="button"
              data-nav-row=""
              className="navtree-head"
              aria-expanded={isOpen}
              aria-controls={listId}
              onClick={() => toggle(gi)}
            >
              <span className="truncate">{group.label}</span>
              <ChevronDown className="navtree-chevron" aria-hidden strokeWidth={2} />
            </button>
            <div className="navtree-fold" data-open={isOpen || undefined}>
              <ul id={listId} className="navtree-list" inert={!isOpen} aria-label={group.label}>
                {group.children.map((item) => {
                  const active = item.value === value;
                  const Icon = item.icon;
                  return (
                    <li key={item.value} className="navtree-item" data-active={active || undefined}>
                      <button
                        type="button"
                        data-nav-row=""
                        {...(isOpen ? {} : { "data-hidden": "" })}
                        className="navtree-row"
                        aria-current={active ? "page" : undefined}
                        aria-label={item.ariaLabel}
                        onClick={() => onSelect(item.value)}
                      >
                        {Icon && <Icon className="navtree-icon" strokeWidth={1.75} />}
                        <span className="min-w-0 flex-1 truncate">{item.label}</span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>
        );
      })}
    </nav>
  );
}
