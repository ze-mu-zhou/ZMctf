import { Wifi, WifiOff } from "lucide-react";
import type { ReactElement } from "react";

import type { ApiHealth } from "../lib/api";
import type { ModuleItem } from "../lib/modules";
import { Badge } from "./Badge";
import { SettingsDialog } from "./SettingsDialog";

export type ConnectionState = "unknown" | "online" | "offline";

export function TopBar(props: {
  module: ModuleItem;
  apiBaseUrl: string;
  health: ApiHealth | null;
  connection: ConnectionState;
  onChangeApiBaseUrl: (next: string) => void;
}): ReactElement {
  const status =
    props.connection === "online"
      ? { icon: <Wifi size={16} />, tone: "ok" as const, text: "后端在线" }
      : props.connection === "offline"
        ? {
            icon: <WifiOff size={16} />,
            tone: "danger" as const,
            text: "后端离线",
          }
        : {
            icon: <span className="zm-pulse">●</span>,
            tone: "muted" as const,
            text: "检测中",
          };

  const version = props.health?.version ?? "unknown";

  return (
    <header className="flex items-center justify-between gap-4">
      <div>
        <div className="text-xs text-muted">ZMctf / 模块</div>
        <div className="text-xl font-semibold tracking-wide">
          {props.module.name}
        </div>
        <div className="mt-1 text-sm text-muted">
          {props.module.description}
        </div>
      </div>

      <div className="flex items-center gap-3">
        <Badge tone={status.tone}>
          {status.icon}
          {status.text} v{version}
        </Badge>

        <SettingsDialog
          apiBaseUrl={props.apiBaseUrl}
          onChangeApiBaseUrl={props.onChangeApiBaseUrl}
        />
      </div>
    </header>
  );
}
