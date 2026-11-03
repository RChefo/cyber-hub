import { Button } from "@heroui/react";
import { ArrowDown, ArrowUp, LayoutGrid, RotateCcw } from "lucide-react";
import { useState, type ComponentType } from "react";
import { useApp } from "@/app/store";
import { AppModal } from "@/components/ui/Dialogs";
import { ErrorBlock } from "@/components/ui/Feedback";
import { SwitchInput } from "@/components/ui/Fields";
import { PageHeader } from "@/components/ui/Panel";
import { cn } from "@/lib/utils";
import {
  ActivityChartWidget,
  ActivityFeedWidget,
  KpiWidget,
  QuickActionsWidget,
  ReadinessWidget,
  RecentCommandsWidget,
  RecentProjectsWidget,
  ResourcesWidget,
  SystemWidget,
  TasksWidget,
  ToolsWidget,
} from "./widgets";

interface WidgetDef {
  id: string;
  title: string;
  component: ComponentType;
  /** columns out of 12 at xl */
  span: 4 | 5 | 6 | 7 | 8 | 12;
}

const WIDGETS: WidgetDef[] = [
  { id: "readiness", title: "Workstation readiness", component: ReadinessWidget, span: 5 },
  { id: "activity-chart", title: "Workspace activity", component: ActivityChartWidget, span: 7 },
  { id: "kpis", title: "Key numbers", component: KpiWidget, span: 12 },
  { id: "activity-feed", title: "Recent activity", component: ActivityFeedWidget, span: 8 },
  { id: "tasks", title: "Pending tasks", component: TasksWidget, span: 4 },
  { id: "tools", title: "Favorite & recent tools", component: ToolsWidget, span: 4 },
  { id: "projects", title: "Recent projects", component: RecentProjectsWidget, span: 4 },
  { id: "quick-actions", title: "Quick actions", component: QuickActionsWidget, span: 4 },
  { id: "commands", title: "Recent commands", component: RecentCommandsWidget, span: 6 },
  { id: "resources", title: "Resource shortcuts", component: ResourcesWidget, span: 6 },
  { id: "system", title: "System information", component: SystemWidget, span: 12 },
];
const DEFAULT_ORDER = WIDGETS.map((w) => w.id);

const SPAN: Record<WidgetDef["span"], string> = {
  4: "xl:col-span-4",
  5: "xl:col-span-5",
  6: "xl:col-span-6",
  7: "xl:col-span-7",
  8: "xl:col-span-8",
  12: "xl:col-span-12",
};

function useLayout() {
  const { prefs, setPref } = useApp();
  const stored = Array.isArray(prefs["dashboard.layout"]) ? (prefs["dashboard.layout"] as string[]) : DEFAULT_ORDER;
  const order = [...stored.filter((id) => DEFAULT_ORDER.includes(id)), ...DEFAULT_ORDER.filter((id) => !stored.includes(id))];
  const hidden = Array.isArray(prefs["dashboard.hidden"]) ? (prefs["dashboard.hidden"] as string[]) : [];
  return {
    order,
    hidden,
    setOrder: (o: string[]) => setPref("dashboard.layout", o),
    setHidden: (h: string[]) => setPref("dashboard.hidden", h),
  };
}

function CustomizeDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { order, hidden, setOrder, setHidden } = useLayout();
  const move = (idx: number, dir: -1 | 1) => {
    const next = [...order];
    const [item] = next.splice(idx, 1);
    next.splice(idx + dir, 0, item);
    setOrder(next);
  };
  return (
    <AppModal
      isOpen={open}
      onOpenChange={onOpenChange}
      title="Customize dashboard"
      description="Choose which widgets appear and in what order. Saved locally."
      footer={
        <>
          <Button
            variant="ghost"
            onPress={() => {
              setOrder(DEFAULT_ORDER);
              setHidden([]);
            }}
          >
            <RotateCcw className="size-3.5" />
            Reset layout
          </Button>
          <Button variant="primary" onPress={() => onOpenChange(false)}>
            Done
          </Button>
        </>
      }
    >
      <ul className="flex flex-col gap-1.5">
        {order.map((id, idx) => {
          const w = WIDGETS.find((x) => x.id === id)!;
          return (
            <li key={id} className="tile flex items-center gap-2 px-3 py-2">
              <div className="flex-1">
                <SwitchInput label={w.title} isSelected={!hidden.includes(id)} onChange={(v) => setHidden(v ? hidden.filter((h) => h !== id) : [...hidden, id])} />
              </div>
              <Button isIconOnly size="sm" variant="ghost" aria-label={`Move ${w.title} up`} isDisabled={idx === 0} onPress={() => move(idx, -1)}>
                <ArrowUp className="size-3.5" />
              </Button>
              <Button isIconOnly size="sm" variant="ghost" aria-label={`Move ${w.title} down`} isDisabled={idx === order.length - 1} onPress={() => move(idx, 1)}>
                <ArrowDown className="size-3.5" />
              </Button>
            </li>
          );
        })}
      </ul>
    </AppModal>
  );
}

export default function Dashboard() {
  const { runtime, catalogError, system } = useApp();
  const { order, hidden } = useLayout();
  const [customize, setCustomize] = useState(false);
  const hour = new Date().getHours();
  const greeting = hour < 12 ? "Good morning" : hour < 18 ? "Good afternoon" : "Good evening";

  return (
    <div>
      <PageHeader
        title={greeting}
        description={
          runtime
            ? `Everything on this page is computed from local data on ${system?.hostname || "this workstation"}. Nothing is sent anywhere.`
            : "Running in a browser preview. Start the desktop app to load local data."
        }
        actions={
          <Button variant="tertiary" size="sm" onPress={() => setCustomize(true)}>
            <LayoutGrid className="size-3.5" />
            Customize
          </Button>
        }
      />
      {catalogError && <ErrorBlock className="mb-4" message={catalogError} />}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2 xl:grid-cols-12">
        {order
          .filter((id) => !hidden.includes(id))
          .map((id) => {
            const w = WIDGETS.find((x) => x.id === id)!;
            const C = w.component;
            return (
              <section key={id} aria-label={w.title} className={cn("min-w-0", w.span === 12 ? "lg:col-span-2" : "", SPAN[w.span])}>
                <C />
              </section>
            );
          })}
      </div>
      <CustomizeDialog open={customize} onOpenChange={setCustomize} />
    </div>
  );
}
