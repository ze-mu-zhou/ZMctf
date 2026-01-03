import { Search } from "lucide-react";
import { type ReactElement, useMemo, useState } from "react";

import { cn } from "../lib/cn";
import type { ModuleItem } from "../lib/modules";
import { Badge } from "./Badge";
import { Card } from "./Card";
import { Input } from "./Input";

export function Sidebar(props: {
  modules: readonly ModuleItem[];
  activeId: string;
  onSelect: (id: string) => void;
}): ReactElement {
  const [query, setQuery] = useState("");
  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      return props.modules;
    }
    return props.modules.filter((m) => {
      const hay = `${m.name}\n${m.description}\n${m.id}`.toLowerCase();
      return hay.includes(q);
    });
  }, [props.modules, query]);

  return (
    <Card className="relative h-full overflow-hidden">
      <div className="absolute inset-0 zm-grid-overlay opacity-40" />
      <div className="relative flex h-full flex-col p-4">
        <div className="mb-4">
          <div className="text-lg font-semibold tracking-wide">ZMctf</div>
          <div className="text-sm text-muted">模块化取证分析套件</div>
        </div>

        <div className="mb-4">
          <div className="relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-muted"
            />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="搜索模块…"
              className="pl-9"
            />
          </div>
          <div className="mt-2 text-xs text-muted">
            {list.length}/{props.modules.length}
          </div>
        </div>

        <nav className="flex-1 overflow-auto pr-1">
          <ul className="space-y-2">
            {list.map((m) => {
              const active = m.id === props.activeId;
              const tone = m.state === "available" ? "accent" : "muted";
              const tag = m.state === "available" ? "可用" : "规划中";

              return (
                <li key={m.id}>
                  <button
                    type="button"
                    onClick={() => props.onSelect(m.id)}
                    className={cn(
                      "w-full rounded-xl border px-3 py-3 text-left transition-colors",
                      "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 focus-visible:ring-offset-2 focus-visible:ring-offset-bg",
                      active
                        ? "border-accent/40 bg-accent/10 shadow-glow"
                        : "border-border/60 bg-panel/30 hover:border-accent/25 hover:bg-panel/50",
                    )}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <div className="font-medium text-text">{m.name}</div>
                      <Badge tone={tone}>{tag}</Badge>
                    </div>
                    <div className="mt-1 text-sm text-muted">
                      {m.description}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="mt-4 text-xs text-muted">
          <div>主目标平台：Windows</div>
          <div className="mt-1">UI：Tauri + React + Tailwind</div>
        </div>
      </div>
    </Card>
  );
}
