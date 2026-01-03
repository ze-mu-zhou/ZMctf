import { type ReactElement, useEffect, useMemo, useState } from "react";

import { FlagDetectorPanel } from "./components/FlagDetectorPanel";
import { OverviewPanel } from "./components/OverviewPanel";
import { Sidebar } from "./components/Sidebar";
import { type ConnectionState, TopBar } from "./components/TopBar";
import type { ApiHealth } from "./lib/api";
import { fetchHealth } from "./lib/api";
import type { ModuleItem } from "./lib/modules";
import { MODULES } from "./lib/modules";
import { readString, writeString } from "./lib/storage";

const API_BASE_URL_KEY = "zmctf.api_base_url";
const DEFAULT_API_BASE_URL = "http://127.0.0.1:8080";

function getDefaultModule(): ModuleItem {
  const first = MODULES[0];
  if (!first) {
    throw new Error("MODULES 不能为空。");
  }
  return first;
}

const DEFAULT_MODULE = getDefaultModule();

function getModuleById(id: string): ModuleItem {
  const found = MODULES.find((m) => m.id === id);
  return found ?? DEFAULT_MODULE;
}

export default function App(): ReactElement {
  const [activeId, setActiveId] = useState(DEFAULT_MODULE.id);
  const [apiBaseUrl, setApiBaseUrl] = useState(() =>
    readString(API_BASE_URL_KEY, DEFAULT_API_BASE_URL),
  );
  const [health, setHealth] = useState<ApiHealth | null>(null);
  const [connection, setConnection] = useState<ConnectionState>("unknown");

  const active = useMemo(() => getModuleById(activeId), [activeId]);

  useEffect(() => {
    writeString(API_BASE_URL_KEY, apiBaseUrl);
  }, [apiBaseUrl]);

  useEffect(() => {
    const controller = new AbortController();

    const tick = async (): Promise<void> => {
      try {
        const h = await fetchHealth(apiBaseUrl, controller.signal);
        setHealth(h);
        setConnection("online");
      } catch {
        setHealth(null);
        setConnection("offline");
      }
    };

    tick().catch(() => undefined);
    const id = window.setInterval(() => {
      tick().catch(() => undefined);
    }, 5000);

    return () => {
      controller.abort();
      window.clearInterval(id);
    };
  }, [apiBaseUrl]);

  return (
    <div className="relative h-screen w-screen overflow-hidden">
      <div className="absolute inset-0 zm-grid-overlay opacity-25" />
      <div className="absolute inset-0 zm-scanlines pointer-events-none" />

      <div className="relative grid h-full grid-cols-1 gap-4 p-4 lg:grid-cols-[360px_1fr]">
        <Sidebar
          modules={MODULES}
          activeId={active.id}
          onSelect={(id) => setActiveId(id)}
        />

        <main className="h-full overflow-auto">
          <div className="mx-auto max-w-[1200px] space-y-4">
            <TopBar
              module={active}
              apiBaseUrl={apiBaseUrl}
              health={health}
              connection={connection}
              onChangeApiBaseUrl={(next) => setApiBaseUrl(next)}
            />

            {active.id === "overview" ? (
              <OverviewPanel
                modules={MODULES}
                apiBaseUrl={apiBaseUrl}
                health={health}
                connection={connection}
                onSelectModule={(id) => setActiveId(id)}
              />
            ) : active.id === "flag-detector" ? (
              <FlagDetectorPanel apiBaseUrl={apiBaseUrl} />
            ) : (
              <div className="mt-6 rounded-xl border border-border/60 bg-panel/40 p-6 text-sm text-muted">
                <div className="text-base font-semibold text-text">占位</div>
                <div className="mt-2">
                  该模块尚未实现。建议下一步先定义统一的“模块接口契约”
                  （输入/输出/日志/证据产物路径/可选外部工具）。
                </div>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
