export interface ApiHealth {
  status: string;
  version: string;
}

export interface AnalyzeRequest {
  content: string;
  mode?: string | null;
}

export interface AnalyzeBytesRequest {
  dataBase64: string;
  fileName?: string | null;
  mode?: string | null;
}

export interface AnalyzeFlag {
  content: string;
  confidence: number;
  source: string;
  encoding: string | null;
}

export interface AnalyzeLogEntry {
  timestamp: string;
  level: string;
  module: string;
  action: string;
}

export interface AnalyzeFileInfo {
  name: string;
  size: number;
  fileType: string;
}

export interface AnalyzeResponse {
  success: boolean;
  flags: AnalyzeFlag[];
  fileInfo: AnalyzeFileInfo | null;
  logs: AnalyzeLogEntry[];
}

type AnalyzeResponseRaw = Record<string, unknown> & {
  success: boolean;
  flags: AnalyzeFlag[];
  logs: AnalyzeLogEntry[];
};

export interface BackendConfigResponse {
  configPath: string;
  config: unknown;
}

export interface BackendDefaultConfigResponse {
  config: unknown;
  toml: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const TRAILING_SLASHES = /\/+$/u;

const FILE_INFO_KEY = "file_info";
const FILE_TYPE_KEY = "file_type";
const CONFIG_PATH_KEY = "config_path";
const CONFIG_KEY = "config";
const TOML_KEY = "toml";
const DATA_BASE64_KEY = "data_base64";
const FILE_NAME_KEY = "file_name";
const MODE_KEY = "mode";

function trimBaseUrl(baseUrl: string): string {
  return baseUrl.trim().replace(TRAILING_SLASHES, "");
}

function parseAnalyzeResponse(data: unknown): AnalyzeResponse {
  const raw = data as AnalyzeResponseRaw;

  const fileInfoRaw = raw[FILE_INFO_KEY];
  const fileInfo = isRecord(fileInfoRaw)
    ? {
        name: typeof fileInfoRaw.name === "string" ? fileInfoRaw.name : "",
        size: typeof fileInfoRaw.size === "number" ? fileInfoRaw.size : 0,
        fileType:
          typeof fileInfoRaw[FILE_TYPE_KEY] === "string"
            ? fileInfoRaw[FILE_TYPE_KEY]
            : "",
      }
    : null;

  return {
    success: raw.success,
    flags: raw.flags,
    fileInfo,
    logs: raw.logs,
  };
}

function parseBackendConfigResponse(data: unknown): BackendConfigResponse {
  if (!isRecord(data)) {
    throw new Error("后端返回的配置不是对象。");
  }
  const raw = data as Record<string, unknown>;
  const configPath = raw[CONFIG_PATH_KEY];
  if (typeof configPath !== "string") {
    throw new Error("后端返回的 config_path 缺失或不是字符串。");
  }
  return {
    configPath,
    config: raw[CONFIG_KEY],
  };
}

function parseBackendDefaultConfigResponse(
  data: unknown,
): BackendDefaultConfigResponse {
  if (!isRecord(data)) {
    throw new Error("后端返回的默认配置不是对象。");
  }
  const raw = data as Record<string, unknown>;
  const toml = raw[TOML_KEY];
  if (typeof toml !== "string") {
    throw new Error("后端返回的 toml 缺失或不是字符串。");
  }
  return {
    config: raw[CONFIG_KEY],
    toml,
  };
}

export async function fetchHealth(
  baseUrl: string,
  signal?: AbortSignal,
): Promise<ApiHealth> {
  const url = `${trimBaseUrl(baseUrl)}/api/health`;
  const init: RequestInit = {};
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    throw new Error(`HTTP ${resp.status}`);
  }
  const data: unknown = await resp.json();
  return data as ApiHealth;
}

export async function analyzeText(
  baseUrl: string,
  request: AnalyzeRequest,
  signal?: AbortSignal,
): Promise<AnalyzeResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/analyze`;
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  };
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseAnalyzeResponse(data);
}

export async function analyzeBytes(
  baseUrl: string,
  request: AnalyzeBytesRequest,
  signal?: AbortSignal,
): Promise<AnalyzeResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/analyze_bytes`;
  const payload: Record<string, unknown> = {};
  payload[DATA_BASE64_KEY] = request.dataBase64;
  payload[FILE_NAME_KEY] = request.fileName ?? null;
  payload[MODE_KEY] = request.mode ?? null;
  const init: RequestInit = {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  };
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseAnalyzeResponse(data);
}

export async function fetchBackendConfig(
  baseUrl: string,
  signal?: AbortSignal,
): Promise<BackendConfigResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/config`;
  const init: RequestInit = {};
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseBackendConfigResponse(data);
}

export async function fetchBackendDefaultConfig(
  baseUrl: string,
  signal?: AbortSignal,
): Promise<BackendDefaultConfigResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/config/default`;
  const init: RequestInit = {};
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseBackendDefaultConfigResponse(data);
}

export async function putBackendConfig(
  baseUrl: string,
  config: unknown,
  signal?: AbortSignal,
): Promise<BackendConfigResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/config`;
  const init: RequestInit = {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  };
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseBackendConfigResponse(data);
}

export async function reloadBackendConfig(
  baseUrl: string,
  signal?: AbortSignal,
): Promise<BackendConfigResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/config/reload`;
  const init: RequestInit = { method: "POST" };
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseBackendConfigResponse(data);
}

export async function resetBackendConfig(
  baseUrl: string,
  signal?: AbortSignal,
): Promise<BackendConfigResponse> {
  const url = `${trimBaseUrl(baseUrl)}/api/config/reset`;
  const init: RequestInit = { method: "POST" };
  if (signal) {
    init.signal = signal;
  }
  const resp = await fetch(url, init);
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${text}`);
  }
  const data: unknown = await resp.json();
  return parseBackendConfigResponse(data);
}
