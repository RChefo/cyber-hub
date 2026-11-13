// SPDX-License-Identifier: MIT
// Adapted from Untitled UI React (https://www.untitledui.com/react/components, MIT; see THIRD_PARTY_NOTICES.md) —
// components/foundations/featured-icon/featured-icon.tsx, "modern" and "light" themes.
// Changes: Untitled UI color tokens are mapped onto HeroUI theme tokens so the icon
// follows the ExploitX design system; unused themes (gradient, dark, outline, modern-neue) removed.
import { isValidElement, type FC, type ReactNode } from "react";
import { cn } from "@/lib/utils";

export type FeaturedIconColor = "brand" | "gray" | "success" | "warning" | "error";

const iconSizes = {
  sm: "[&>svg]:size-4",
  md: "[&>svg]:size-[18px]",
  lg: "[&>svg]:size-5",
};

const styles = {
  light: {
    base: "rounded-full",
    sizes: { sm: "size-8", md: "size-10", lg: "size-12" },
    colors: {
      brand: "bg-accent-soft text-accent-soft-foreground",
      gray: "bg-default text-muted",
      error: "bg-danger-soft text-danger-soft-foreground",
      warning: "bg-warning-soft text-warning-soft-foreground",
      success: "bg-success-soft text-success-soft-foreground",
    },
  },
  modern: {
    base: "bg-surface-secondary shadow-[inset_0_1px_0_rgba(255,255,255,0.05)] ring-1 ring-border ring-inset",
    sizes: { sm: "size-8 rounded-md", md: "size-9 rounded-lg", lg: "size-11 rounded-[10px]" },
    colors: {
      brand: "text-accent-soft-foreground",
      gray: "text-muted",
      error: "text-danger-soft-foreground",
      warning: "text-warning-soft-foreground",
      success: "text-success-soft-foreground",
    },
  },
} as const;

interface FeaturedIconProps {
  className?: string;
  icon: FC<{ className?: string }> | ReactNode;
  size?: keyof typeof iconSizes;
  color?: FeaturedIconColor;
  theme?: keyof typeof styles;
}

// Lucide icons are forwardRef objects, not plain functions, so check for an element first.
function renderIcon(Icon: FeaturedIconProps["icon"]) {
  if (Icon == null || typeof Icon === "boolean") return null;
  if (isValidElement(Icon) || typeof Icon === "string" || typeof Icon === "number") return Icon;
  const Component = Icon as FC<{ className?: string }>;
  return <Component />;
}

export function FeaturedIcon({ className, icon: Icon, size = "sm", color = "gray", theme = "modern" }: FeaturedIconProps) {
  return (
    <div
      data-featured-icon
      className={cn(
        "relative flex shrink-0 items-center justify-center",
        iconSizes[size],
        styles[theme].base,
        styles[theme].sizes[size],
        styles[theme].colors[color],
        className,
      )}
    >
      {renderIcon(Icon)}
    </div>
  );
}
