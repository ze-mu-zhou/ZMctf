export interface ApiHealth {
  status: string;
  version: string;
}

export interface AnalyzeRequest {
  content: string;
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

const TRAILING_SLASHES = /\/+$/u;

const FILE_INFO_KEY = "file_info";
const FILE_TYPE_KEY = "file_type";

function trimBaseUrl(baseUrl: string): string {
  return baseUrl.trim().replace(TRAILING_SLASHES, "");
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
