import type { HTMLAttributes, ReactElement } from "react";

import { cn } from "../lib/cn";

export function Card({
  className,
  ...props
}: HTMLAttributes<HTMLDivElement>): ReactElement {
  return (
    <div
      {...props}
      className={cn(
        "rounded-xl border border-border/70 bg-panel/60 backdrop-blur",
        className,
      )}
    />
  );
}
