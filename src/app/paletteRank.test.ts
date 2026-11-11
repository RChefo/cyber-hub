import { describe, expect, it } from "vitest";
import { PER_GROUP, rank, score } from "./paletteRank";

const item = (group: string, title: string, rest = "") => ({ group, title, haystack: `${title} ${rest}`.toLowerCase() });
const titles = (xs: { title: string }[]) => xs.map((x) => x.title);

describe("command palette ranking", () => {
  // Mission 9, GNOME session: Ctrl+K, "RC", Enter opened Cyber Resources instead of the project
  it("puts a project whose name starts with the query before pages that only contain it", () => {
    const items = [
      item("Pages", "Cyber Resources", "curated security websites"),
      item("Pages", "OSINT Workspace", "investigations and public-source data"),
      item("Tools", "Aircrack-ng", "suite for assessing wi-fi security"),
      item("Projects", "RC validation", "active"),
    ];
    const r = rank(items, "RC");
    expect(r[0].title).toBe("RC validation");
    expect(titles(r)).toEqual(["RC validation", "Cyber Resources", "OSINT Workspace", "Aircrack-ng"]);
  });

  it("keeps the usual group order when the best matches are equally strong", () => {
    const r = rank([item("Projects", "Project Alpha"), item("Pages", "Projects", "engagements")], "proj");
    expect(titles(r)).toEqual(["Projects", "Project Alpha"]);
  });

  it("orders a group by score, keeps groups together and caps each group", () => {
    const tools = Array.from({ length: 9 }, (_, n) => item("Tools", `scanner ${n}`, "nmap wrapper"));
    const r = rank([...tools, item("Tools", "Nmap", "network mapper"), item("Commands", "nmap: version scan")], "nmap");
    expect(r[0].title).toBe("Nmap");
    expect(r.filter((x) => x.group === "Tools")).toHaveLength(PER_GROUP);
    expect(r.map((x) => x.group)).toEqual([...Array(PER_GROUP).fill("Tools"), "Commands"]);
  });

  it("needs every term, and returns nothing for an empty query", () => {
    expect(rank([item("Projects", "RC validation")], "rc zzz")).toEqual([]);
    expect(rank([item("Projects", "RC validation")], "   ")).toEqual([]);
    expect(score(item("Pages", "Settings"), ["set", "tin"])).toBe(10);
  });

  it("places groups matched elsewhere by their fixed score", () => {
    const records = [item("Records", "SQL injection in login")];
    const r = rank([item("Commands", "sqlmap", "sql injection automation"), item("Projects", "SQL audit")], "sql", [{ group: "Records", items: records, score: 4 }]);
    expect(r.map((x) => x.group)).toEqual(["Projects", "Commands", "Records"]);
    const weak = rank([item("Resources", "Cheat sheets", "sql injection")], "sql", [{ group: "Records", items: records, score: 4 }]);
    expect(weak.map((x) => x.group)).toEqual(["Records", "Resources"]);
  });
});
