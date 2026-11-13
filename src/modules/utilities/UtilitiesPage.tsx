// SPDX-License-Identifier: Apache-2.0
import { Button, Tooltip } from "@heroui/react";
import { CloudUpload, Star } from "lucide-react";
import type { ComponentType } from "react";
import { useApp } from "@/app/store";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";
import { UTILITIES, type UtilityDef, type UtilityId } from "./registry";
import { HashCalcTool, HashIdTool, JwtTool, UserAgentTool } from "./tools/AnalysisTools";
import { Base64Tool, HexTool, UrlTool } from "./tools/EncodingTools";
import { DnsTool, HeadersTool, IpTool, UrlParserTool } from "./tools/NetworkTools";
import { HtmlTool, JsonTool, RegexTool, XmlTool } from "./tools/TextTools";
import { IocTool } from "./tools/IocTool";
import { WorkbenchTool } from "./tools/Workbench";
import { DnsIntelTool, HttpBuilderTool, PortsTool, SecretsTool, SubdomainMonitorTool, TlsTool } from "./tools/AssessmentTools";
import { CloudTool } from "./tools/CloudTool";
import { FileTriageTool } from "./tools/FileTriageTool";
import { LinuxTool } from "./tools/LinuxTool";
import { OAuthTool } from "./tools/OAuthTool";
import { ContainerTool } from "./tools/ContainerTool";
import { CaptureTool, LogTool } from "./tools/TriageTools";

const VIEWS: Record<UtilityId, ComponentType> = {
  workbench: WorkbenchTool,
  base64: Base64Tool,
  url: UrlTool,
  hex: HexTool,
  jwt: JwtTool,
  "hash-id": HashIdTool,
  "hash-calc": HashCalcTool,
  ioc: IocTool,
  regex: RegexTool,
  json: JsonTool,
  xml: XmlTool,
  html: HtmlTool,
  "url-parser": UrlParserTool,
  ip: IpTool,
  dns: DnsTool,
  headers: HeadersTool,
  "user-agent": UserAgentTool,
  "http-builder": HttpBuilderTool,
  tls: TlsTool,
  oauth: OAuthTool,
  "dns-intel": DnsIntelTool,
  ports: PortsTool,
  "subdomain-monitor": SubdomainMonitorTool,
  secrets: SecretsTool,
  containers: ContainerTool,
  cloud: CloudTool,
  "file-triage": FileTriageTool,
  "linux-persistence": LinuxTool,
  pcap: CaptureTool,
  logs: LogTool,
};

const GROUP_ORDER: UtilityDef["group"][] = ["Encoding", "Analysis", "Formatting", "Network", "Assessment"];

function UtilityLink({ u, active, onSelect }: { u: UtilityDef; active: boolean; onSelect: () => void }) {
  const Icon = u.icon;
  return (
    <Button
      variant="ghost"
      onPress={onSelect}
      aria-current={active ? "page" : undefined}
      className={cn(
        "h-8 w-full justify-start gap-2.5 rounded-md px-2.5 text-[13.5px] font-normal",
        active ? "bg-white/[0.06] text-foreground hover:bg-white/[0.07]" : "text-muted hover:bg-white/[0.035] hover:text-foreground",
      )}
    >
      <Icon className={cn("size-4 shrink-0", active ? "text-accent-soft-foreground" : "text-muted")} strokeWidth={1.75} />
      <span className="truncate">{u.name}</span>
      {u.network && <CloudUpload className="ml-auto size-3.5 shrink-0 text-muted/70" aria-label="Makes a network request" />}
    </Button>
  );
}

export default function UtilitiesPage() {
  const { route, navigate, isFavorite, toggleFavorite } = useApp();
  const selectedId = (UTILITIES.some((u) => u.id === route.params?.utility) ? route.params!.utility : "workbench") as UtilityId;
  const selected = UTILITIES.find((u) => u.id === selectedId)!;
  const View = VIEWS[selectedId];
  const favs = UTILITIES.filter((u) => isFavorite("utility", u.id));
  const select = (id: UtilityId) => navigate("utilities", { utility: id });
  const fav = isFavorite("utility", selectedId);

  const groups: { label: string; items: UtilityDef[] }[] = [
    ...(favs.length ? [{ label: "Favorites", items: favs }] : []),
    ...GROUP_ORDER.map((g) => ({ label: g, items: UTILITIES.filter((u) => u.group === g) })),
  ];

  return (
    <div>
      <PageHeader
        title="Security Utilities"
        description="Encoders, decoders, parsers and analyzers. Everything runs on this device except the tools marked as making network requests, which send them only when you press their run button."
      />
      <div className="grid gap-3 lg:grid-cols-[240px_minmax(0,1fr)]">
        <nav className="panel h-fit p-2 lg:sticky lg:top-0" aria-label="Utilities">
          {groups.map((g) => (
            <div key={g.label} className="mb-2 last:mb-0">
              <div className="px-2.5 pt-1.5 pb-1 text-[11.5px] font-medium text-muted/80">{g.label}</div>
              <div className="flex flex-col gap-0.5">
                {g.items.map((u) => (
                  <UtilityLink key={`${g.label}-${u.id}`} u={u} active={u.id === selectedId} onSelect={() => select(u.id)} />
                ))}
              </div>
            </div>
          ))}
        </nav>
        <Panel
          title={selected.name}
          description={selected.description}
          actions={
            <Tooltip delay={400}>
              <Button isIconOnly size="sm" variant="ghost" aria-label={fav ? `Remove ${selected.name} from favorites` : `Add ${selected.name} to favorites`} onPress={() => toggleFavorite("utility", selectedId, selected.name)}>
                <Star className={cn("size-4", fav ? "fill-warning text-warning" : "text-muted")} />
              </Button>
              <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
            </Tooltip>
          }
          className="min-w-0"
        >
          <View key={selectedId} />
        </Panel>
      </div>
    </div>
  );
}
