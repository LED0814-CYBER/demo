import type { PatchStatusRaw } from "./contracts";

export type TaskStage = "IDLE" | "UPLOADING" | "QUEUED" | "SCANNING" | "REPORT_READY" | "FAILED";

export type RequestState = "IDLE" | "PENDING" | "SUCCESS" | "ERROR";

export type WsConnectionState =
  | "DISCONNECTED"
  | "CONNECTING"
  | "CONNECTED"
  | "RECONNECTING"
  | "DEGRADED"
  | "FAILED";

export type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

export type StatusTone = "danger" | "warn" | "safe" | "muted" | "unknown";

export type NormalizedPatchStatus =
  | "PRESENT"
  | "NOT_PRESENT"
  | "PATCH_PRESENT"
  | "PATCH_NOT_PRESENT"
  | "DEAD_CODE"
  | "UNKNOWN"
  | "HUNG"
  | "ERROR"
  | "RESOURCE_LIMIT";

export interface PatchStatusSemantic {
  rawStatus: PatchStatusRaw;
  normalizedStatus: NormalizedPatchStatus;
  label: string;
  color: StatusTone;
  severity: SeverityLevel;
  isSafe: boolean;
  isReachable: boolean;
  conclusion: string;
}

export interface ApkInfoModel {
  name: string;
  sha256: string;
  size: number;
}

export interface UsedLibraryModel {
  id: string;
  rawName: string;
  libraryName: string;
  group: string;
  artifact: string;
  version: string;
  confidence: number;
  vulnerabilityCount: number;
  maxSeverity: SeverityLevel;
}

export interface VulnerabilityModel {
  id: string;
  cveId: string;
  library: string;
  status: PatchStatusSemantic;
  preSimilarity: number | null;
  postSimilarity: number | null;
  raw: {
    status: PatchStatusRaw;
    pre_similarity: number | null;
    post_similarity: number | null;
  };
}

export interface ReportSummary {
  total: number;
  highRisk: number;
  mediumRisk: number;
  safeCount: number;
  unknownCount: number;
  libraryCount: number;
}

export interface ReportModel {
  taskId: string;
  reportPath: string;
  apkInfo: ApkInfoModel;
  usedLibraries: UsedLibraryModel[];
  vulnerabilities: VulnerabilityModel[];
  summary: ReportSummary;
}

export interface LogEntry {
  id: string;
  message: string;
  source: "system" | "meta" | "stdout" | "stderr" | "socket";
  timestamp: number;
}

export interface UploadContext {
  fileName: string;
  size: number;
  uploadedPath?: string;
}
