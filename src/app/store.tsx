import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import type { OsId, ToolCatalog, ToolDef } from "@/types/catalog";
import { notify } from "@/lib/actions";
import { api, errorMessage, runtimeAvailable } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Detection, FavoriteKind, SystemInfo } from "@/lib/types";
import type { PageId } from "./routes";

export interface Route {
  page: PageId;
  params?: Record<string, string>;
}

interface AppState {
  route: Route;
  navigate: (page: PageId, params?: Record<string, string>) => void;
  runtime: boolean;
  os: OsId;
  system: SystemInfo | undefined;
  catalog: ToolCatalog | undefined;
  catalogError: string | null;
  toolById: (id: string) => ToolDef | undefined;
  detections: Map<string, Detection>;
  scanning: boolean;
  scanTools: (probeVersions: boolean, toolIds?: string[]) => Promise<void>;
  isFavorite: (kind: FavoriteKind, id: string) => boolean;
  toggleFavorite: (kind: FavoriteKind, id: string, label?: string) => Promise<void>;
  favorites: { kind: FavoriteKind; itemId: string }[];
  prefs: Record<string, unknown>;
  setPref: (key: string, value: unknown) => Promise<void>;
  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;
}

const Ctx = createContext<AppState | null>(null);

function guessOs(): OsId {
  const p = navigator.userAgent.toLowerCase();
  if (p.includes("win")) return "windows";
  if (p.includes("mac")) return "macos";
  return "linux";
}

export function AppProvider({ children }: { children: ReactNode }) {
  const runtime = runtimeAvailable();
  const [route, setRoute] = useState<Route>({ page: "dashboard" });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [scanning, setScanning] = useState(false);

  const system = useQuery(["system"], api.systemInfo, [], runtime);
  const catalog = useQuery([], api.toolsCatalog, [], runtime);
  const detections = useQuery(["detections"], api.toolsDetectionList, [], runtime);
  const favorites = useQuery(["favorites"], api.favoritesList, [], runtime);
  const prefs = useQuery(["prefs"], api.prefsGetAll, [], runtime);

  const navigate = useCallback((page: PageId, params?: Record<string, string>) => {
    setRoute({ page, params });
    document.getElementById("main-scroll")?.scrollTo({ top: 0 });
  }, []);

  const toolMap = useMemo(() => new Map((catalog.data?.tools ?? []).map((t) => [t.id, t])), [catalog.data]);
  const detectionMap = useMemo(() => new Map((detections.data ?? []).map((d) => [d.toolId, d])), [detections.data]);
  const favSet = useMemo(() => new Set((favorites.data ?? []).map((f) => `${f.kind}:${f.itemId}`)), [favorites.data]);

  const scanTools = useCallback(async (probeVersions: boolean, toolIds?: string[]) => {
    setScanning(true);
    try {
      const res = await api.toolsScan(probeVersions, toolIds);
      const found = res.filter((d) => d.status === "installed" || d.status === "dependency_missing").length;
      invalidate("detections", "activity", "prefs");
      if (!toolIds) notify.success("Tool scan complete", `${found} of ${res.length} catalog tools found on this system.`);
    } catch (e) {
      notify.error("Tool scan failed", e);
    } finally {
      setScanning(false);
    }
  }, []);

  const toggleFavorite = useCallback(async (kind: FavoriteKind, id: string, label?: string) => {
    try {
      const on = await api.favoriteToggle(kind, id);
      invalidate("favorites");
      if (label) notify.success(on ? `Added ${label} to favorites` : `Removed ${label} from favorites`);
    } catch (e) {
      notify.error("Could not update favorites", e);
    }
  }, []);

  const setPref = useCallback(async (key: string, value: unknown) => {
    try {
      await api.prefsSet(key, value);
      invalidate("prefs");
    } catch (e) {
      notify.error("Could not save preference", errorMessage(e));
    }
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const value: AppState = {
    route,
    navigate,
    runtime,
    os: system.data?.os ?? guessOs(),
    system: system.data,
    catalog: catalog.data,
    catalogError: catalog.error,
    toolById: (id) => toolMap.get(id),
    detections: detectionMap,
    scanning,
    scanTools,
    isFavorite: (kind, id) => favSet.has(`${kind}:${id}`),
    toggleFavorite,
    favorites: favorites.data ?? [],
    prefs: prefs.data ?? {},
    setPref,
    paletteOpen,
    setPaletteOpen,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp(): AppState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used within AppProvider");
  return v;
}
