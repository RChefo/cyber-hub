import { Area, AreaChart, CartesianGrid, XAxis, YAxis } from "recharts";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/vendor/shadcn/chart";

export interface ActivityPoint {
  date: string; // YYYY-MM-DD
  label: string;
  events: number;
}

const config = {
  events: { label: "Events", color: "var(--accent)" },
} satisfies ChartConfig;

/**
 * Single-series activity-over-time area (shadcn Charts + Recharts).
 * One series → no legend; the panel title names it. Crosshair tooltip on hover.
 */
export function ActivityAreaChart({ data, height = 190 }: { data: ActivityPoint[]; height?: number }) {
  const step = Math.max(1, Math.ceil(data.length / 8));
  return (
    <ChartContainer config={config} className="aspect-auto w-full" style={{ height }}>
      <AreaChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: -18 }}>
        <defs>
          <linearGradient id="fill-events" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--color-events)" stopOpacity={0.32} />
            <stop offset="100%" stopColor="var(--color-events)" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.05)" />
        <XAxis
          dataKey="label"
          tickLine={false}
          axisLine={false}
          interval={step - 1}
          tickMargin={8}
          tick={{ fontSize: 11 }}
        />
        <YAxis allowDecimals={false} tickLine={false} axisLine={false} width={40} tick={{ fontSize: 11 }} />
        <ChartTooltip cursor={{ stroke: "rgba(255,255,255,0.18)", strokeWidth: 1 }} content={<ChartTooltipContent indicator="line" />} />
        <Area
          dataKey="events"
          type="monotone"
          stroke="var(--color-events)"
          strokeWidth={2}
          fill="url(#fill-events)"
          activeDot={{ r: 4, strokeWidth: 2, stroke: "var(--surface)" }}
          isAnimationActive={false}
        />
      </AreaChart>
    </ChartContainer>
  );
}
