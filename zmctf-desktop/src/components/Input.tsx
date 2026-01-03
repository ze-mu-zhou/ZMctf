import type { InputHTMLAttributes, ReactElement } from "react";

import { cn } from "../lib/cn";

export function Input({
  className,
  ...props
}: InputHTMLAttributes<HTMLInputElement>): ReactElement {
  return (
    <input
      {...props}
      className={cn(
        "w-full rounded-lg border border-border/70 bg-bg/30 px-3 py-2 text-sm text-text placeholder:text-muted/70",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
        className,
      )}
    />
  );
}
