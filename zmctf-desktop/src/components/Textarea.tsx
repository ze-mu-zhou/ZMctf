import type { ReactElement, TextareaHTMLAttributes } from "react";

import { cn } from "../lib/cn";

export function Textarea({
  className,
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>): ReactElement {
  return (
    <textarea
      {...props}
      className={cn(
        "w-full resize-y rounded-lg border border-border/70 bg-bg/30 px-3 py-2 text-sm text-text placeholder:text-muted/70",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
        className,
      )}
    />
  );
}
