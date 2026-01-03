import { Check, Copy } from "lucide-react";
import { type ReactElement, useState } from "react";

import { Button } from "./Button";

export function CopyButton(props: {
  value: string;
  label: string;
}): ReactElement {
  const [copied, setCopied] = useState(false);

  const onCopy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(props.value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Button
      variant="ghost"
      onClick={() => {
        onCopy().catch(() => undefined);
      }}
      aria-label={props.label}
      title={props.label}
      className="px-2 py-2"
    >
      {copied ? <Check size={16} /> : <Copy size={16} />}
    </Button>
  );
}
