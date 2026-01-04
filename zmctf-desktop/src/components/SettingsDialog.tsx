import {
  Close,
  Content,
  Description,
  Overlay,
  Portal,
  Root,
  Title,
  Trigger,
} from "@radix-ui/react-dialog";
import { Settings2, X } from "lucide-react";
import { type ReactElement, useEffect, useState } from "react";

import {
  fetchBackendConfig,
  fetchBackendDefaultConfig,
  putBackendConfig,
  reloadBackendConfig,
  resetBackendConfig,
} from "../lib/api";
import { Button } from "./Button";
import { Card } from "./Card";
import { Input } from "./Input";
import { Textarea } from "./Textarea";

type SettingsTab = "connection" | "backend";

type JsonParseResult =
  | { ok: true; value: unknown }
  | { ok: false; error: string };

function tryParseJson(text: string): JsonParseResult {
  try {
    const value: unknown = JSON.parse(text);
    return { ok: true, value };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "未知错误";
    return { ok: false, error: msg };
  }
}

function formatJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function toErrorMessage(e: unknown): string {
  return e instanceof Error ? e.message : "未知错误";
}

export function SettingsDialog(props: {
  apiBaseUrl: string;
  onChangeApiBaseUrl: (next: string) => void;
}): ReactElement {
  const [draft, setDraft] = useState(props.apiBaseUrl);
  const [tab, setTab] = useState<SettingsTab>("connection");

  const [backendBusy, setBackendBusy] = useState(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [backendInfo, setBackendInfo] = useState<string | null>(null);
  const [backendConfigPath, setBackendConfigPath] = useState<string | null>(
    null,
  );
  const [backendConfigText, setBackendConfigText] = useState("");
  const [defaultToml, setDefaultToml] = useState<string | null>(null);

  useEffect(() => {
    setDraft(props.apiBaseUrl);
  }, [props.apiBaseUrl]);

  const loadConfig = async (): Promise<void> => {
    setBackendBusy(true);
    setBackendError(null);
    setBackendInfo(null);
    try {
      const resp = await fetchBackendConfig(props.apiBaseUrl);
      setBackendConfigPath(resp.configPath);
      setBackendConfigText(formatJson(resp.config));
      setBackendInfo("已从后端加载当前配置。");
    } catch (e) {
      setBackendError(`加载失败：${toErrorMessage(e)}`);
    } finally {
      setBackendBusy(false);
    }
  };

  const reloadConfig = async (): Promise<void> => {
    setBackendBusy(true);
    setBackendError(null);
    setBackendInfo(null);
    try {
      const resp = await reloadBackendConfig(props.apiBaseUrl);
      setBackendConfigPath(resp.configPath);
      setBackendConfigText(formatJson(resp.config));
      setBackendInfo("已从磁盘重载配置并应用到运行态。");
    } catch (e) {
      setBackendError(`重载失败：${toErrorMessage(e)}`);
    } finally {
      setBackendBusy(false);
    }
  };

  const loadDefaultConfig = async (): Promise<void> => {
    setBackendBusy(true);
    setBackendError(null);
    setBackendInfo(null);
    try {
      const resp = await fetchBackendDefaultConfig(props.apiBaseUrl);
      setBackendConfigText(formatJson(resp.config));
      setDefaultToml(resp.toml);
      setBackendInfo("已载入默认配置（尚未保存到后端）。");
    } catch (e) {
      setBackendError(`获取默认配置失败：${toErrorMessage(e)}`);
    } finally {
      setBackendBusy(false);
    }
  };

  const resetConfig = async (): Promise<void> => {
    setBackendBusy(true);
    setBackendError(null);
    setBackendInfo(null);
    try {
      const resp = await resetBackendConfig(props.apiBaseUrl);
      setBackendConfigPath(resp.configPath);
      setBackendConfigText(formatJson(resp.config));
      setBackendInfo("已重置为默认配置并保存到后端。");
    } catch (e) {
      setBackendError(`重置失败：${toErrorMessage(e)}`);
    } finally {
      setBackendBusy(false);
    }
  };

  const saveConfig = async (): Promise<void> => {
    const parsed = tryParseJson(backendConfigText);
    if (!parsed.ok) {
      setBackendError(`配置不是合法 JSON：${parsed.error}`);
      return;
    }

    setBackendBusy(true);
    setBackendError(null);
    setBackendInfo(null);
    try {
      const resp = await putBackendConfig(props.apiBaseUrl, parsed.value);
      setBackendConfigPath(resp.configPath);
      setBackendConfigText(formatJson(resp.config));
      setBackendInfo("已保存并应用配置。");
    } catch (e) {
      setBackendError(`保存失败：${toErrorMessage(e)}`);
    } finally {
      setBackendBusy(false);
    }
  };

  const formatDraftConfig = (): void => {
    const parsed = tryParseJson(backendConfigText);
    if (!parsed.ok) {
      setBackendError(`配置不是合法 JSON：${parsed.error}`);
      return;
    }
    setBackendError(null);
    setBackendConfigText(formatJson(parsed.value));
  };

  return (
    <Root>
      <Trigger asChild={true}>
        <Button variant="outline">
          <Settings2 size={16} />
          设置
        </Button>
      </Trigger>

      <Portal>
        <Overlay className="fixed inset-0 bg-black/55 backdrop-blur-sm" />
        <Content className="fixed left-1/2 top-1/2 h-[82vh] w-[980px] max-w-[96vw] -translate-x-1/2 -translate-y-1/2 focus:outline-none">
          <Card className="relative h-full overflow-hidden p-5">
            <div className="absolute inset-0 zm-grid-overlay opacity-25" />
            <div className="relative flex h-full flex-col">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <Title className="text-lg font-semibold">设置</Title>
                  <Description className="mt-1 text-sm text-muted">
                    连接配置 + 后端配置中心（后端有的配置，这里都能改）
                  </Description>
                </div>
                <Close asChild={true}>
                  <Button variant="ghost" aria-label="关闭">
                    <X size={18} />
                  </Button>
                </Close>
              </div>

              <div className="mt-4 flex items-center gap-2 rounded-xl border border-border/60 bg-bg/20 p-1">
                <button
                  type="button"
                  className={
                    tab === "connection"
                      ? "flex-1 rounded-lg bg-panel/60 px-3 py-2 text-sm font-medium text-text shadow-glow"
                      : "flex-1 rounded-lg px-3 py-2 text-sm font-medium text-muted hover:text-text"
                  }
                  onClick={() => setTab("connection")}
                >
                  连接
                </button>
                <button
                  type="button"
                  className={
                    tab === "backend"
                      ? "flex-1 rounded-lg bg-panel/60 px-3 py-2 text-sm font-medium text-text shadow-glow"
                      : "flex-1 rounded-lg px-3 py-2 text-sm font-medium text-muted hover:text-text"
                  }
                  onClick={() => setTab("backend")}
                >
                  后端配置
                </button>
              </div>

              <div className="mt-4 flex-1 overflow-hidden">
                {tab === "connection" ? (
                  <div className="h-full overflow-auto pr-1">
                    <div className="space-y-2">
                      <label
                        className="text-sm text-muted"
                        htmlFor="apiBaseUrl"
                      >
                        API Base URL
                      </label>
                      <Input
                        id="apiBaseUrl"
                        value={draft}
                        onChange={(e) => setDraft(e.target.value)}
                        placeholder="http://127.0.0.1:8080"
                      />
                      <div className="text-xs text-muted">
                        提示：如果你把后端绑定到 0.0.0.0，请自行评估暴露风险。
                      </div>
                    </div>

                    <div className="mt-5 flex items-center justify-end gap-3">
                      <Close asChild={true}>
                        <Button variant="ghost">关闭</Button>
                      </Close>
                      <Button
                        onClick={() => props.onChangeApiBaseUrl(draft)}
                        variant="primary"
                      >
                        应用
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div className="flex h-full flex-col gap-3 overflow-hidden">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-sm font-medium text-text">
                          后端配置中心
                        </div>
                        <div className="mt-1 text-xs text-muted">
                          当前连接：{props.apiBaseUrl}
                          {backendConfigPath
                            ? ` · config_path：${backendConfigPath}`
                            : ""}
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          variant="outline"
                          disabled={backendBusy}
                          onClick={() => {
                            loadConfig().catch(() => undefined);
                          }}
                        >
                          加载
                        </Button>
                        <Button
                          variant="outline"
                          disabled={backendBusy}
                          onClick={() => {
                            reloadConfig().catch(() => undefined);
                          }}
                        >
                          重载
                        </Button>
                        <Button
                          variant="outline"
                          disabled={backendBusy}
                          onClick={() => {
                            loadDefaultConfig().catch(() => undefined);
                          }}
                        >
                          默认
                        </Button>
                        <Button
                          variant="outline"
                          disabled={backendBusy}
                          onClick={() => {
                            resetConfig().catch(() => undefined);
                          }}
                        >
                          重置并保存
                        </Button>
                        <Button
                          variant="outline"
                          disabled={backendBusy}
                          onClick={() => formatDraftConfig()}
                        >
                          格式化
                        </Button>
                        <Button
                          variant="primary"
                          disabled={backendBusy}
                          onClick={() => {
                            saveConfig().catch(() => undefined);
                          }}
                        >
                          保存并应用
                        </Button>
                      </div>
                    </div>

                    {backendError ? (
                      <div
                        role="alert"
                        aria-live="polite"
                        className="rounded-lg border border-magenta/35 bg-magenta/10 px-3 py-2 text-sm text-magenta"
                      >
                        {backendError}
                      </div>
                    ) : null}

                    {backendInfo ? (
                      <div className="rounded-lg border border-accent/25 bg-accent/8 px-3 py-2 text-sm text-text">
                        {backendInfo}
                      </div>
                    ) : null}

                    <div className="flex-1 overflow-hidden rounded-xl border border-border/60 bg-bg/20">
                      <div className="flex items-center justify-between border-b border-border/60 px-3 py-2">
                        <div className="text-sm font-medium text-text">
                          AppConfig (JSON)
                        </div>
                        <div className="text-xs text-muted">
                          保存时会写入后端 `config.toml`
                        </div>
                      </div>
                      <div className="h-full overflow-auto p-3">
                        <Textarea
                          value={backendConfigText}
                          onChange={(e) => setBackendConfigText(e.target.value)}
                          placeholder="点“加载”从后端拉取当前 AppConfig，然后在这里编辑 JSON。"
                          rows={18}
                          className="min-h-[420px] font-mono text-xs"
                        />
                      </div>
                    </div>

                    {defaultToml ? (
                      <div className="rounded-xl border border-border/60 bg-bg/20 p-3">
                        <div className="text-sm font-medium text-text">
                          默认 config.toml（只读）
                        </div>
                        <Textarea
                          value={defaultToml}
                          readOnly={true}
                          rows={6}
                          className="mt-2 font-mono text-xs"
                        />
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            </div>
          </Card>
        </Content>
      </Portal>
    </Root>
  );
}
