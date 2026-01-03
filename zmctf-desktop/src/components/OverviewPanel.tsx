import { Layers3, Rocket, Server } from "lucide-react";
import type { ReactElement } from "react";

import type { ApiHealth } from "../lib/api";
import type { ModuleItem } from "../lib/modules";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import type { ConnectionState } from "./TopBar";

function connectionBadge(connection: ConnectionState): {
  tone: "ok" | "danger" | "muted";
  text: string;
} {
  if (connection === "online") {
    return { tone: "ok", text: "后端在线" };
  }
  if (connection === "offline") {
    return { tone: "danger", text: "后端离线" };
  }
  return { tone: "muted", text: "检测中" };
}

export function OverviewPanel(props: {
  modules: readonly ModuleItem[];
  apiBaseUrl: string;
  health: ApiHealth | null;
  connection: ConnectionState;
  onSelectModule: (id: string) => void;
}): ReactElement {
  const available = props.modules.filter((m) => m.state === "available");
  const planned = props.modules.filter((m) => m.state === "planned");
  const status = connectionBadge(props.connection);

  const version = props.health?.version ?? "unknown";

  return (
    <div className="mt-6 space-y-4">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="relative overflow-hidden p-4">
          <div className="absolute inset-0 zm-grid-overlay opacity-15" />
          <div className="relative">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium text-text">
                <Server size={16} />
                后端
              </div>
              <Badge tone={status.tone}>{status.text}</Badge>
            </div>
            <div className="mt-3 space-y-1 text-sm text-muted">
              <div className="flex items-center justify-between gap-3">
                <span>版本</span>
                <span className="font-mono text-text">{version}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span>API</span>
                <span className="max-w-[70%] truncate font-mono text-text">
                  {props.apiBaseUrl}
                </span>
              </div>
            </div>
          </div>
        </Card>

        <Card className="relative overflow-hidden p-4">
          <div className="absolute inset-0 zm-grid-overlay opacity-15" />
          <div className="relative">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium text-text">
                <Layers3 size={16} />
                模块
              </div>
              <Badge tone="muted">
                {available.length} 可用 / {planned.length} 规划
              </Badge>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {available.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => props.onSelectModule(m.id)}
                  className="rounded-full border border-accent/25 bg-accent/10 px-2.5 py-1 text-xs text-accent transition-colors hover:bg-accent/15"
                >
                  {m.name}
                </button>
              ))}
            </div>
          </div>
        </Card>

        <Card className="relative overflow-hidden p-4">
          <div className="absolute inset-0 zm-grid-overlay opacity-15" />
          <div className="relative">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-sm font-medium text-text">
                <Rocket size={16} />
                快速入口
              </div>
              <Badge tone="accent">工作台</Badge>
            </div>
            <div className="mt-3 space-y-2">
              <Button
                className="w-full justify-start"
                onClick={() => props.onSelectModule("flag-detector")}
              >
                打开 Flag Detector
              </Button>
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => props.onSelectModule("usb")}
              >
                USB 流量还原（规划中）
              </Button>
            </div>
            <div className="mt-3 text-xs text-muted">
              建议先启动后端：
              <span className="font-mono">flag-detector/core</span> →
              <span className="font-mono">zmctf-server</span>。
            </div>
          </div>
        </Card>
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm font-medium text-text">路线图（规划中）</div>
          <Badge tone="muted">{planned.length} 项</Badge>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {planned.slice(0, 14).map((m) => (
            <span
              key={m.id}
              className="rounded-full border border-border/70 bg-panel/40 px-2.5 py-1 text-xs text-muted"
              title={m.description}
            >
              {m.name}
            </span>
          ))}
          {planned.length > 14 ? (
            <span className="rounded-full border border-border/70 bg-panel/40 px-2.5 py-1 text-xs text-muted">
              +{planned.length - 14}
            </span>
          ) : null}
        </div>
      </Card>
    </div>
  );
}
