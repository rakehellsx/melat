export function fmtBytes(n: number | null | undefined): string {
  if (n == null || isNaN(n)) return "-";
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)}KB`;
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)}MB`;
  return `${(n / 1073741824).toFixed(2)}GB`;
}

export function fmtTime(d: Date | string | null | undefined): string {
  if (!d) return "-";
  const dt = typeof d === "string" ? new Date(d) : d;
  const p = (x: number) => String(x).padStart(2, "0");
  return `${dt.getFullYear()}-${p(dt.getMonth() + 1)}-${p(dt.getDate())} ${p(dt.getHours())}:${p(dt.getMinutes())}:${p(dt.getSeconds())}`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}min`;
}

export const SEVERITY_STYLE: Record<string, { label: string; color: string; bg: string }> = {
  critical: { label: "严重", color: "#ff4444", bg: "rgba(255,68,68,0.12)" },
  high: { label: "高危", color: "#ff8c42", bg: "rgba(255,140,66,0.12)" },
  medium: { label: "中危", color: "#ffd166", bg: "rgba(255,209,102,0.12)" },
  low: { label: "低危", color: "#6b7280", bg: "rgba(107,114,128,0.15)" },
};

export const CATEGORY_STYLE: Record<string, { label: string; color: string }> = {
  attack: { label: "入侵攻击", color: "#ff8c42" },
  c2: { label: "C&C 通信", color: "#ff4444" },
  data: { label: "数据安全", color: "#00d9a3" },
  baseline: { label: "基线异常", color: "#7aa2ff" },
  custom: { label: "自定义模型", color: "#9d7aff" },
};

export const FIELD_TYPE_LABEL: Record<string, string> = {
  string: "字符串", number: "数值", ip: "IP", port: "端口",
  time: "时间", enum: "枚举", boolean: "布尔", ratio: "比率",
};
