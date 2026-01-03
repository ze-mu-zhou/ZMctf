import type { ButtonHTMLAttributes, ReactElement } from "react";

import { cn } from "../lib/cn";

export type ButtonVariant = "primary" | "outline" | "ghost";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
}

export function Button({
  className,
  variant = "primary",
  type = "button",
  ...props
}: ButtonProps): ReactElement {
  const variants: Record<ButtonVariant, string> = {
    primary:
      "bg-accent/15 text-accent border-accent/35 shadow-glow hover:bg-accent/18 hover:shadow-glowStrong active:bg-accent/20",
    outline:
      "bg-transparent text-text border-border/70 hover:border-accent/40 hover:text-accent",
    ghost: "bg-transparent text-muted border-transparent hover:text-text",
  };

  return (
    <button
      {...props}
      type={type}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium",
        "transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
        "disabled:cursor-not-allowed disabled:opacity-50",
        variants[variant],
        className,
      )}
    />
  );
}
