// Types for the React Bits OrbitImages component (JavaScript + CSS variant), see OrbitImages.jsx.
import type { ReactNode } from "react";

export interface OrbitImagesProps {
  images?: Array<string | { src: string; alt?: string }>;
  altPrefix?: string;
  shape?: "ellipse" | "circle" | "square" | "rectangle" | "triangle" | "star" | "heart" | "infinity" | "wave" | "custom";
  customPath?: string;
  baseWidth?: number;
  radiusX?: number;
  radiusY?: number;
  radius?: number;
  starPoints?: number;
  starInnerRatio?: number;
  rotation?: number;
  duration?: number;
  itemSize?: number;
  direction?: "normal" | "reverse";
  fill?: boolean;
  depth?: number;
  alignToPath?: boolean;
  itemRadius?: number | string;
  shadow?: number;
  hoverScale?: number;
  hoverSpeed?: number;
  draggable?: boolean;
  clickToFront?: boolean;
  onItemClick?: (index: number, src: string) => void;
  showPath?: boolean;
  pathColor?: string;
  pathWidth?: number;
  pathDash?: number;
  easing?: "linear" | "easeIn" | "easeOut" | "easeInOut";
  paused?: boolean;
  intro?: boolean;
  centerContent?: ReactNode;
  width?: number | string;
  height?: number | string;
  className?: string;
}

export default function OrbitImages(props: OrbitImagesProps): ReactNode;
