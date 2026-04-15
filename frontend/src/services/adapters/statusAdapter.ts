import type { NormalizedPatchStatus, PatchStatusSemantic } from "../../types/domain";
import type { PatchStatusRaw } from "../../types/contracts";

function normalize(rawStatus: PatchStatusRaw | null | undefined): NormalizedPatchStatus {
  const value = String(rawStatus || "UNKNOWN").trim().toUpperCase();

  switch (value) {
    case "PRESENT":
      return "PRESENT";
    case "NOT_PRESENT":
      return "NOT_PRESENT";
    case "PATCH_PRESENT":
      return "PATCH_PRESENT";
    case "PATCH_NOT_PRESENT":
      return "PATCH_NOT_PRESENT";
    case "DEAD_CODE":
      return "DEAD_CODE";
    case "HUNG":
      return "HUNG";
    case "ERROR":
      return "ERROR";
    case "RESOURCE_LIMIT":
      return "RESOURCE_LIMIT";
    default:
      return "UNKNOWN";
  }
}

export function adaptPatchStatus(rawStatus: PatchStatusRaw | null | undefined): PatchStatusSemantic {
  const normalizedStatus = normalize(rawStatus);

  const table: Record<NormalizedPatchStatus, Omit<PatchStatusSemantic, "rawStatus" | "normalizedStatus">> = {
    PRESENT: {
      label: "漏洞存在",
      color: "danger",
      severity: "critical",
      isSafe: false,
      isReachable: true,
      conclusion: "漏洞特征仍存在，存在真实可利用风险。",
    },
    NOT_PRESENT: {
      label: "未检测到漏洞",
      color: "safe",
      severity: "low",
      isSafe: true,
      isReachable: false,
      conclusion: "未检测到漏洞特征，当前版本风险较低。",
    },
    PATCH_PRESENT: {
      label: "补丁已应用",
      color: "safe",
      severity: "low",
      isSafe: true,
      isReachable: false,
      conclusion: "补丁已验证，漏洞已被修复。",
    },
    PATCH_NOT_PRESENT: {
      label: "补丁未应用",
      color: "danger",
      severity: "high",
      isSafe: false,
      isReachable: true,
      conclusion: "补丁未应用，存在真实风险。",
    },
    DEAD_CODE: {
      label: "代码不可达",
      color: "muted",
      severity: "info",
      isSafe: true,
      isReachable: false,
      conclusion: "漏洞位置不可达或已被裁剪，当前不构成直接威胁。",
    },
    UNKNOWN: {
      label: "状态未知",
      color: "unknown",
      severity: "medium",
      isSafe: false,
      isReachable: true,
      conclusion: "证据不足，建议继续复核以确认真实风险。",
    },
    HUNG: {
      label: "验证超时",
      color: "warn",
      severity: "medium",
      isSafe: false,
      isReachable: true,
      conclusion: "补丁验证超时，需补充离线复核。",
    },
    ERROR: {
      label: "验证异常",
      color: "warn",
      severity: "medium",
      isSafe: false,
      isReachable: true,
      conclusion: "验证流程发生错误，建议复跑并人工确认。",
    },
    RESOURCE_LIMIT: {
      label: "资源受限",
      color: "warn",
      severity: "medium",
      isSafe: false,
      isReachable: true,
      conclusion: "验证因资源受限中断，当前结论需谨慎使用。",
    },
  };

  return {
    rawStatus: rawStatus ?? "UNKNOWN",
    normalizedStatus,
    ...table[normalizedStatus],
  };
}

export function mapBackendTaskStatusToStage(status: string): "QUEUED" | "SCANNING" | "REPORT_READY" | "FAILED" {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "completed") return "REPORT_READY";
  if (normalized === "failed") return "FAILED";
  if (normalized === "running") return "SCANNING";
  return "QUEUED";
}
