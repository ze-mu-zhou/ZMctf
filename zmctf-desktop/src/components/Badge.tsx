import type { ReactElement, ReactNode } from "react";

import { cn } from "../lib/cn";

export type BadgeTone = "accent" | "muted" | "danger" | "ok";

export function Badge(props: {
  children: ReactNode;
  tone?: BadgeTone;
  className?: string;
}): ReactElement {
  const tone = props.tone ?? "muted";
  const cls: Record<BadgeTone, string> = {
    accent:
      "border-accent/30 text-accent bg-accent/10 shadow-[0_0_24px_hsl(var(--zm-accent)/0.10)]",
    muted: "border-border/70 text-muted bg-panel/40",
    ok: "border-cyan/30 text-cyan bg-cyan/10 shadow-[0_0_24px_hsl(var(--zm-cyan)/0.10)]",
    danger:
      "border-magenta/30 text-magenta bg-magenta/10 shadow-[0_0_24px_hsl(var(--zm-magenta)/0.10)]",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs font-medium",
        cls[tone],
        props.className,
      )}
    >
      {props.children}
    </span>
  );
}
