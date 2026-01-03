export function readString(key: string, fallback: string): string {
  try {
    const raw = localStorage.getItem(key);
    return raw ?? fallback;
  } catch {
    return fallback;
  }
}

export function writeString(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // 忽略：在受限环境中 localStorage 可能不可用
  }
}
