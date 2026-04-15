import type { SeverityLevel } from "../types/domain";

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

export function formatRatio(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "-";
  return `${(value * 100).toFixed(1)}%`;
}

export function clamp01(value: number | null | undefined): number {
  if (value == null || !Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

export function severityRank(level: SeverityLevel): number {
  switch (level) {
    case "critical":
      return 5;
    case "high":
      return 4;
    case "medium":
      return 3;
    case "low":
      return 2;
    default:
      return 1;
  }
}

export function shortHash(value: string): string {
  if (!value) return "-";
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}...${value.slice(-8)}`;
}
