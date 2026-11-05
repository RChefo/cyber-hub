import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import type { RefObject } from "react";

gsap.registerPlugin(useGSAP, ScrollTrigger);

/** Motion is allowed only when the visitor has not asked for less of it. */
export const MOTION_OK = "(prefers-reduced-motion: no-preference)";
/** Larger, scroll-linked effects (parallax) are kept to wider screens. */
export const DESKTOP = "(prefers-reduced-motion: no-preference) and (min-width: 1024px)";

/**
 * Staggered reveal of every `[data-reveal]` element inside `scope` as it scrolls into view.
 * Everything is created inside a gsap.matchMedia context, so it is skipped for reduced motion
 * and reverted (tweens and ScrollTriggers killed) when the component unmounts.
 */
export function useReveal(scope: RefObject<HTMLElement | null>) {
  useGSAP(
    () => {
      const mm = gsap.matchMedia();
      mm.add(MOTION_OK, () => {
        const groups = gsap.utils.toArray<HTMLElement>("[data-reveal-group]", scope.current);
        const targets = groups.length ? groups : [scope.current!];
        for (const group of targets) {
          const items = gsap.utils.toArray<HTMLElement>("[data-reveal]", group);
          if (!items.length) continue;
          gsap.from(items, {
            autoAlpha: 0,
            y: 22,
            duration: 0.8,
            ease: "power3.out",
            stagger: 0.08,
            scrollTrigger: { trigger: group, start: "top 82%", once: true },
          });
        }
      });
      return () => mm.revert();
    },
    { scope },
  );
}

export { gsap, ScrollTrigger, useGSAP };
