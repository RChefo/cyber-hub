// SPDX-License-Identifier: Apache-2.0
/**
 * Severity distribution (ECharts, built on the vendored EvilCharts core).
 * Severity is ordinal status: every bar carries its name on the category axis and a
 * direct value label, so color is never the only encoding (dataviz skill, check 4).
 */
import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { DEFAULT_ECHARTS_RENDERER } from "@/components/vendor/evilcharts/echarts-chart";
import type { Severity } from "@/lib/types";

echarts.use([BarChart, GridComponent, TooltipComponent]);

const COLORS: Record<Severity, string> = {
  critical: "#e5484d",
  high: "#f2803a",
  medium: "#f2c94c",
  low: "#4c9bff",
  info: "#9aa3b5",
};
const LABELS: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
const ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function SeverityBarChart({ counts, height = 180, include = ORDER }: { counts: Partial<Record<Severity, number>>; height?: number; include?: Severity[] }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current, undefined, { renderer: DEFAULT_ECHARTS_RENDERER });
    const sev = ORDER.filter((s) => include.includes(s));
    chart.setOption({
      animation: false,
      grid: { left: 70, right: 36, top: 4, bottom: 4 },
      tooltip: {
        trigger: "item",
        backgroundColor: "#171b22",
        borderColor: "rgba(255,255,255,0.08)",
        textStyle: { color: "#eceef4", fontSize: 12, fontFamily: "IBM Plex Sans" },
        formatter: (p: { name: string; value: number }) => `${p.name}: <b>${p.value}</b>`,
      },
      xAxis: { type: "value", show: false, minInterval: 1 },
      yAxis: {
        type: "category",
        inverse: true,
        data: sev.map((s) => LABELS[s]),
        axisLine: { show: false },
        axisTick: { show: false },
        axisLabel: { color: "#8b92a5", fontSize: 12, fontFamily: "IBM Plex Sans" },
      },
      series: [
        {
          type: "bar",
          barWidth: 12,
          showBackground: true,
          backgroundStyle: { color: "rgba(255,255,255,0.035)", borderRadius: 4 },
          itemStyle: { borderRadius: [0, 4, 4, 0] },
          label: { show: true, position: "right", color: "#eceef4", fontSize: 12, fontFamily: "IBM Plex Sans" },
          data: sev.map((s) => ({ value: counts[s] ?? 0, name: LABELS[s], itemStyle: { color: COLORS[s] } })),
        },
      ],
    });
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      chart.dispose();
    };
  }, [counts, include]);

  return <div ref={ref} style={{ height }} className="w-full" role="img" aria-label={ORDER.filter((s) => include.includes(s)).map((s) => `${LABELS[s]}: ${counts[s] ?? 0}`).join(", ")} />;
}
