// SPDX-License-Identifier: MIT
// Adapted from Lightswind (https://lightswind.com/components) — registry item `dot-pattern`. License: MIT (npm package
// lightswind); see THIRD_PARTY_NOTICES.md.
// Changes: typed props (no `any` index signature), `cn` import path, and the motion class
// removed so the texture is static (restrained motion per the ExploitX design brief).
import { useId, type SVGProps } from "react";
import { cn } from "@/lib/utils";

interface DotPatternProps extends Omit<SVGProps<SVGSVGElement>, "width" | "height" | "x" | "y"> {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  cx?: number;
  cy?: number;
  cr?: number;
  className?: string;
}

export function DotPattern({ width = 16, height = 16, x = 0, y = 0, cx = 1, cy = 1, cr = 1, className, ...props }: DotPatternProps) {
  const id = useId();

  return (
    <svg aria-hidden="true" className={cn("pointer-events-none absolute inset-0 h-full w-full fill-neutral-400/80", className)} {...props}>
      <defs>
        <pattern id={id} width={width} height={height} x={x} y={y} patternUnits="userSpaceOnUse" patternTransform="translate(0,0)">
          <circle cx={cx} cy={cy} r={cr} />
        </pattern>
      </defs>
      <rect width="100%" height="100%" strokeWidth={0} fill={`url(#${id})`} />
    </svg>
  );
}

export default DotPattern;
