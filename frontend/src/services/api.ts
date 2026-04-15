import type { AnalyzeResponseRaw, ReportResponseRaw, UploadResponseRaw } from "../types/contracts";

export class ApiError extends Error {
  readonly status: number;
  readonly payload?: unknown;

  constructor(message: string, status: number, payload?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

async function requestJson<T>(input: RequestInfo | URL, init?: RequestInit): Promise<T> {
  const response = await fetch(input, init);
  let payload: unknown = null;

  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const detail =
      typeof payload === "object" && payload && "detail" in payload
        ? String((payload as { detail?: string }).detail || "")
        : "";
    throw new ApiError(detail || `Request failed (${response.status})`, response.status, payload);
  }

  return payload as T;
}

export async function uploadApk(file: File): Promise<UploadResponseRaw> {
  const form = new FormData();
  form.append("file", file);
  return requestJson<UploadResponseRaw>("/api/upload", {
    method: "POST",
    body: form,
  });
}

export async function startAnalyze(uploadResult: Pick<UploadResponseRaw, "filename">): Promise<AnalyzeResponseRaw> {
  return requestJson<AnalyzeResponseRaw>("/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ filename: uploadResult.filename }),
  });
}

export async function fetchReport(taskId: string): Promise<ReportResponseRaw> {
  return requestJson<ReportResponseRaw>(`/api/report?task_id=${encodeURIComponent(taskId)}`);
}
