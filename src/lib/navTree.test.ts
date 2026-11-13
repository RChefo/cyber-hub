import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { NavTree } from "@/components/ui/NavTree";
import { initialOpen, nextFocus } from "./navTree";

const Icon = () => createElement("svg", { "data-icon": "" });
const groups = [
  { label: "Workspace", children: [{ value: "dashboard", label: "Dashboard", icon: Icon }, { value: "projects", label: "Projects", icon: Icon }] },
  { label: "Research", children: [{ value: "osint", label: "OSINT Workspace", icon: Icon }, { value: "mcp", label: createElement("span", null, "MCP ", createElement("b", null, "2")), ariaLabel: "MCP, 2 waiting for approval" }] },
];

describe("NavTree (replaces the React Bits BranchedMenu, Mission 14)", () => {
  it("moves focus with the arrow keys, Home and End, wrapping around", () => {
    expect(nextFocus(0, 4, "ArrowDown")).toBe(1);
    expect(nextFocus(3, 4, "ArrowDown")).toBe(0);
    expect(nextFocus(0, 4, "ArrowUp")).toBe(3);
    expect(nextFocus(-1, 4, "ArrowDown")).toBe(0);
    expect(nextFocus(-1, 4, "ArrowUp")).toBe(3);
    expect(nextFocus(2, 4, "Home")).toBe(0);
    expect(nextFocus(1, 4, "End")).toBe(3);
    expect(nextFocus(1, 4, "Enter")).toBeNull(); // Enter and Space stay with the buttons
    expect(nextFocus(0, 0, "ArrowDown")).toBeNull();
  });

  it("opens every group by default, a given set otherwise, and always the active item's group", () => {
    expect([...initialOpen(groups, undefined)]).toEqual([0, 1]);
    expect([...initialOpen(groups, "dashboard", [])]).toEqual([0]);
    expect([...initialOpen(groups, "mcp", [0])].sort()).toEqual([0, 1]);
  });

  it("renders disclosure buttons, the current page and accessible names", () => {
    const html = renderToStaticMarkup(createElement(NavTree, { groups, value: "projects", onSelect: () => {}, "aria-label": "Sections" }));
    expect(html).toContain('<nav aria-label="Sections" class="navtree">');
    expect((html.match(/aria-expanded="true"/g) ?? []).length).toBe(2);
    // exactly one current page, on the active item
    expect((html.match(/aria-current="page"/g) ?? []).length).toBe(1);
    expect(html).toMatch(/aria-current="page"[^>]*>(<svg[^>]*><\/svg>)?<span[^>]*>Projects<\/span>/);
    // the group holding the active item is marked for its accent bar; the other is not
    expect((html.match(/class="navtree-group" data-active="true"/g) ?? []).length).toBe(1);
    // a rich label keeps a plain accessible name
    expect(html).toContain('aria-label="MCP, 2 waiting for approval"');
    // every list is labelled by its group and controlled by its header
    for (const m of html.matchAll(/aria-controls="([^"]+)"/g)) expect(html).toContain(`id="${m[1]}"`);
  });

  it("marks closed groups and keeps their rows out of the keyboard order", () => {
    const html = renderToStaticMarkup(createElement(NavTree, { groups, value: "dashboard", openGroups: [], onSelect: () => {} }));
    expect((html.match(/aria-expanded="false"/g) ?? []).length).toBe(1); // Research (Workspace holds the active page)
    expect(html).toMatch(/<ul[^>]*inert=""[^>]*aria-label="Research"|<ul[^>]*aria-label="Research"[^>]*inert=""/);
    expect((html.match(/data-hidden=""/g) ?? []).length).toBe(2);
  });
});
