export type PatchStatusRaw =
  | "PRESENT"
  | "NOT_PRESENT"
  | "PATCH_PRESENT"
  | "PATCH_NOT_PRESENT"
  | "DEAD_CODE"
  | "UNKNOWN"
  | "HUNG"
  | "ERROR"
  | "RESOURCE_LIMIT"
  | string;

export interface UploadResponseRaw {
  message: string;
  filename: string;
  path: string;
  size: number;
}

export interface AnalyzeTaskRaw {
  task_id: string;
  apk_name: string;
  apk_path: string;
  status: string;
  celery_task_id?: string | null;
  report_path?: string | null;
  stdout_log_path?: string | null;
  stderr_log_path?: string | null;
  error?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
}

export interface AnalyzeResponseRaw {
  message: string;
  task: AnalyzeTaskRaw;
}

export interface ApkInfoRaw {
  name?: string;
  sha256?: string;
  size?: number;
}

export interface UsedLibraryRaw {
  raw_name?: string;
  library_name?: string;
  version?: string;
  similarity?: number;
}

export interface VulnerabilityRaw {
  cve_id?: string;
  library?: string;
  status?: PatchStatusRaw;
  pre_similarity?: number | null;
  post_similarity?: number | null;
}

export interface ReportRaw {
  apk_info?: ApkInfoRaw;
  used_libraries?: UsedLibraryRaw[];
  vulnerabilities?: VulnerabilityRaw[];
}

export interface ReportResponseRaw {
  task_id?: string | null;
  report_path?: string;
  report?: ReportRaw;
}

export interface WsMetaMessageRaw {
  type: "meta";
  task_id: string;
  apk_name: string;
  status: string;
}

export interface WsLogMessageRaw {
  type: "log";
  task_id: string;
  file?: string;
  message?: string;
}

export interface WsDoneMessageRaw {
  type: "done";
  task_id: string;
  status: "completed" | "failed" | string;
  error?: string | null;
  report_path?: string | null;
}

export interface WsErrorMessageRaw {
  type: "error";
  message: string;
  task_id?: string;
}

export type TaskLogMessageRaw =
  | WsMetaMessageRaw
  | WsLogMessageRaw
  | WsDoneMessageRaw
  | WsErrorMessageRaw;
