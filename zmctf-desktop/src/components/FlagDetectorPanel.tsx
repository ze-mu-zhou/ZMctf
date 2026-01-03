import { type ReactElement, useRef, useState } from "react";

import type { AnalyzeResponse } from "../lib/api";
import { analyzeText } from "../lib/api";
import { Badge } from "./Badge";
import { Button } from "./Button";
import { Card } from "./Card";
import { CopyButton } from "./CopyButton";
import { Textarea } from "./Textarea";

const SAMPLE = `这是一个测试：
flag{test123}
还有一个 rot13：synt{grfg123}`;

export function FlagDetectorPanel(props: {
  apiBaseUrl: string;
}): ReactElement {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resp, setResp] = useState<AnalyzeResponse | null>(null);

  const controllerRef = useRef<AbortController | null>(null);

  const onAnalyze = async (): Promise<void> => {
    const content = input.trim();
    if (!content) {
      setError("请输入待分析内容。");
      return;
    }

    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;

    setBusy(true);
    setError(null);
    setResp(null);

    try {
      const data = await analyzeText(
        props.apiBaseUrl,
        { content, mode: null },
        controller.signal,
      );
      setResp(data);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "未知错误";
      setError(`分析失败：${msg}`);
    } finally {
      setBusy(false);
    }
  };

  const summary = resp
    ? { flags: resp.flags.length, logs: resp.logs.length }
    : null;

  return (
    <div className="mt-6 space-y-4">
      <Card className="relative overflow-hidden p-4">
        <div className="absolute inset-0 zm-grid-overlay opacity-20" />
        <div className="relative">
          <div className="flex items-center justify-between gap-3">
            <div className="text-sm font-medium text-text">输入</div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                onClick={() => setInput(SAMPLE)}
                disabled={busy}
              >
                填充示例
              </Button>
              <Button
                onClick={() => {
                  onAnalyze().catch(() => undefined);
                }}
                disabled={busy}
              >
                {busy ? "分析中…" : "开始分析"}
              </Button>
            </div>
          </div>

          <div className="mt-3">
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="粘贴文本 / 解码链产物 / 还原的协议内容等…"
              rows={8}
            />
          </div>

          {error ? (
            <div
              role="alert"
              aria-live="polite"
              className="mt-3 rounded-lg border border-magenta/35 bg-magenta/10 px-3 py-2 text-sm text-magenta"
            >
              {error}
            </div>
          ) : null}
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="p-4">
          <div className="text-xs text-muted">flags</div>
          <div className="mt-1 text-2xl font-semibold">
            {summary ? summary.flags : "—"}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-muted">logs</div>
          <div className="mt-1 text-2xl font-semibold">
            {summary ? summary.logs : "—"}
          </div>
        </Card>
        <Card className="p-4">
          <div className="text-xs text-muted">api</div>
          <div className="mt-1 break-all text-sm text-text">
            {props.apiBaseUrl}
          </div>
        </Card>
      </div>

      <Card className="p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm font-medium text-text">Flag 列表</div>
          <Badge tone={resp ? "accent" : "muted"}>
            {resp ? `共 ${resp.flags.length} 条` : "未分析"}
          </Badge>
        </div>

        <div className="mt-3 space-y-3">
          {resp && resp.flags.length > 0 ? (
            resp.flags.map((f) => {
              const key = `${f.content}::${f.source}`;
              const pct = Math.max(0, Math.min(1, f.confidence));
              const bar = `${Math.round(pct * 100)}%`;

              return (
                <div
                  key={key}
                  className="rounded-xl border border-border/60 bg-bg/20 p-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="break-all font-mono text-sm text-text">
                        {f.content}
                      </div>
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted">
                        <span>confidence</span>
                        <span className="font-mono">
                          {f.confidence.toFixed(3)}
                        </span>
                        <span>source</span>
                        <span className="truncate font-mono">{f.source}</span>
                      </div>
                    </div>
                    <CopyButton value={f.content} label="复制 Flag" />
                  </div>

                  <div className="mt-3">
                    <div className="h-2 w-full rounded-full bg-border/40">
                      <div
                        className="h-2 rounded-full bg-accent/70 shadow-[0_0_16px_hsl(var(--zm-accent)/0.30)]"
                        style={{ width: bar }}
                      />
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="text-sm text-muted">暂无结果。</div>
          )}
        </div>
      </Card>

      <Card className="p-4">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm font-medium text-text">日志</div>
          <Badge tone="muted">
            {resp ? `共 ${resp.logs.length} 条` : "未分析"}
          </Badge>
        </div>

        <div className="mt-3 max-h-[260px] overflow-auto rounded-xl border border-border/60 bg-bg/20 p-3 font-mono text-xs">
          {resp && resp.logs.length > 0 ? (
            resp.logs.map((l) => {
              const key = `${l.timestamp}::${l.module}::${l.level}::${l.action}`;
              const tone =
                l.level === "error"
                  ? "danger"
                  : l.level === "warn"
                    ? "muted"
                    : "muted";

              return (
                <div
                  key={key}
                  className="mb-2 flex flex-wrap items-center gap-2"
                >
                  <span className="text-muted">{l.timestamp}</span>
                  <Badge tone={tone}>{l.level}</Badge>
                  <span className="text-muted">{l.module}</span>
                  <span className="break-all text-text">{l.action}</span>
                </div>
              );
            })
          ) : (
            <div className="text-muted">暂无日志。</div>
          )}
        </div>
      </Card>
    </div>
  );
}
