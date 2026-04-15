import type { ReportResponseRaw, UsedLibraryRaw, VulnerabilityRaw } from "../../types/contracts";
import type { ReportModel, SeverityLevel, UsedLibraryModel, VulnerabilityModel } from "../../types/domain";
import { buildVulnerabilityId } from "../../utils/identity";
import { adaptLibrary } from "./libraryAdapter";
import { adaptPatchStatus } from "./statusAdapter";

function toNumber(value: unknown): number | null {
  return Number.isFinite(value) ? Number(value) : null;
}

function severityOrder(level: SeverityLevel): number {
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

function adaptVulnerability(raw: VulnerabilityRaw): VulnerabilityModel {
  const cveId = raw.cve_id || "UNKNOWN-CVE";
  const library = raw.library || "unknown:unknown";
  const status = adaptPatchStatus(raw.status);
  const pre = toNumber(raw.pre_similarity);
  const post = toNumber(raw.post_similarity);

  return {
    id: buildVulnerabilityId(cveId, library),
    cveId,
    library,
    status,
    preSimilarity: pre,
    postSimilarity: post,
    raw: {
      status: raw.status ?? "UNKNOWN",
      pre_similarity: pre,
      post_similarity: post,
    },
  };
}

function buildLibraryModels(rawLibraries: UsedLibraryRaw[], vulnerabilities: VulnerabilityModel[]): UsedLibraryModel[] {
  const byLibrary = vulnerabilities.reduce<Record<string, { count: number; max: SeverityLevel }>>((acc, vuln) => {
    const curr = acc[vuln.library] || { count: 0, max: "info" as SeverityLevel };
    acc[vuln.library] = {
      count: curr.count + 1,
      max:
        severityOrder(vuln.status.severity) > severityOrder(curr.max)
          ? vuln.status.severity
          : curr.max,
    };
    return acc;
  }, {});

  const models = rawLibraries.map((lib) => {
    const meta = byLibrary[lib.library_name || ""];
    return adaptLibrary(lib, meta?.count ?? 0, meta?.max ?? "info");
  });

  if (models.length > 0) return models;

  // 当后端未返回 used_libraries 时，用漏洞中出现的库兜底生成最小 SBOM 视图。
  const uniqueLibraries = Array.from(new Set(vulnerabilities.map((v) => v.library)));
  return uniqueLibraries.map((name) => {
    const meta = byLibrary[name];
    return adaptLibrary(
      {
        library_name: name,
        version: "-",
        similarity: 0,
        raw_name: "",
      },
      meta?.count ?? 0,
      meta?.max ?? "info",
    );
  });
}

export function adaptReport(raw: ReportResponseRaw, fallbackTaskId: string): ReportModel {
  const report = raw.report || {};
  const vulnerabilities = (report.vulnerabilities || []).map(adaptVulnerability);
  const usedLibraries = buildLibraryModels(report.used_libraries || [], vulnerabilities).sort((a, b) => {
    if (b.vulnerabilityCount !== a.vulnerabilityCount) return b.vulnerabilityCount - a.vulnerabilityCount;
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    return a.libraryName.localeCompare(b.libraryName);
  });

  const summary = vulnerabilities.reduce(
    (acc, vuln) => {
      acc.total += 1;
      if (vuln.status.isSafe) acc.safeCount += 1;
      if (!vuln.status.isSafe && vuln.status.severity !== "medium" && vuln.status.severity !== "info") acc.highRisk += 1;
      if (vuln.status.severity === "medium" || vuln.status.severity === "info") acc.mediumRisk += 1;
      if (["UNKNOWN", "HUNG", "ERROR", "RESOURCE_LIMIT"].includes(vuln.status.normalizedStatus)) {
        acc.unknownCount += 1;
      }
      return acc;
    },
    {
      total: 0,
      highRisk: 0,
      mediumRisk: 0,
      safeCount: 0,
      unknownCount: 0,
      libraryCount: usedLibraries.length,
    },
  );

  return {
    taskId: raw.task_id || fallbackTaskId,
    reportPath: raw.report_path || "",
    apkInfo: {
      name: report.apk_info?.name || "unknown.apk",
      sha256: report.apk_info?.sha256 || "",
      size: Number.isFinite(report.apk_info?.size) ? Number(report.apk_info?.size) : 0,
    },
    usedLibraries,
    vulnerabilities,
    summary,
  };
}
