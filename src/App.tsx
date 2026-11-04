import { Toast } from "@heroui/react";
import { Component, lazy, Suspense, type ComponentType, type ReactNode } from "react";
import { CommandPalette } from "@/app/CommandPalette";
import { McpApprovals } from "@/app/McpApprovals";
import type { PageId } from "@/app/routes";
import { Sidebar } from "@/app/Sidebar";
import { AppProvider, useApp } from "@/app/store";
import { Topbar } from "@/app/Topbar";
import { ErrorBlock, LoadingRows } from "@/components/ui/Feedback";

const PAGES: Record<PageId, React.LazyExoticComponent<ComponentType>> = {
  dashboard: lazy(() => import("@/modules/dashboard/Dashboard")),
  projects: lazy(() => import("@/modules/projects/ProjectsPage")),
  runs: lazy(() => import("@/modules/runs/RunsPage")),
  tools: lazy(() => import("@/modules/tools/ToolsPage")),
  commands: lazy(() => import("@/modules/commands/CommandCenter")),
  payloads: lazy(() => import("@/modules/payloads/PayloadsPage")),
  dorks: lazy(() => import("@/modules/dorks/DorksStudio")),
  resources: lazy(() => import("@/modules/resources/ResourcesPage")),
  intel: lazy(() => import("@/modules/intel/IntelPage")),
  virustotal: lazy(() => import("@/modules/virustotal/VirusTotalPage")),
  threatintel: lazy(() => import("@/modules/threatintel/ThreatIntelPage")),
  utilities: lazy(() => import("@/modules/utilities/UtilitiesPage")),
  mcp: lazy(() => import("@/modules/mcp/McpPage")),
  settings: lazy(() => import("@/modules/settings/SettingsPage")),
};

class PageErrorBoundary extends Component<{ children: ReactNode; resetKey: string }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  render() {
    if (this.state.error) return <ErrorBlock message={`This page failed to render: ${this.state.error.message}`} />;
    return this.props.children;
  }
}

function Main() {
  const { route } = useApp();
  const Page = PAGES[route.page];
  const key = `${route.page}:${JSON.stringify(route.params ?? {})}`;
  return (
    <main id="main-scroll" className="scroll-area flex-1 px-6 pt-5 pb-10">
      <div className="mx-auto max-w-[1480px]">
        <PageErrorBoundary resetKey={key}>
          <Suspense fallback={<LoadingRows rows={6} />}>
            <Page key={route.page} />
          </Suspense>
        </PageErrorBoundary>
      </div>
    </main>
  );
}

export default function App() {
  return (
    <AppProvider>
      <div className="flex h-full">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <Main />
        </div>
      </div>
      <CommandPalette />
      <McpApprovals />
      <Toast.Provider placement="bottom end" />
    </AppProvider>
  );
}
