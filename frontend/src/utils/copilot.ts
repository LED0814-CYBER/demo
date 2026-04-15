import type { ReportModel, VulnerabilityModel } from "../types/domain";
import { formatRatio } from "./format";

function statusGuidance(vuln: VulnerabilityModel): string {
  if (vuln.status.normalizedStatus === "PATCH_NOT_PRESENT" || vuln.status.normalizedStatus === "PRESENT") {
    return "建议立即安排修复窗口，优先验证受影响调用链并制定热修复方案。";
  }
  if (vuln.status.normalizedStatus === "PATCH_PRESENT" || vuln.status.normalizedStatus === "NOT_PRESENT") {
    return "当前证据显示补丁生效，可作为修复完成项在答辩中展示。";
  }
  if (vuln.status.normalizedStatus === "DEAD_CODE") {
    return "该漏洞位于不可达代码路径，建议保留为低优先级技术债跟踪项。";
  }
  return "建议补充动态验证或人工复核，以降低误报和漏报风险。";
}

export function buildCopilotNarrative(vuln: VulnerabilityModel | null, report: ReportModel | null): string {
  if (!vuln || !report) {
    return "请选择一个漏洞条目。副屏会基于当前报告实时生成可答辩的安全分析结论。";
  }

  return [
    `分析对象：${vuln.cveId} @ ${vuln.library}`,
    `结论：${vuln.status.conclusion}`,
    `补丁判定：${vuln.status.label}（原始状态 ${String(vuln.status.rawStatus || "UNKNOWN")}）`,
    `证据：Pre Similarity ${formatRatio(vuln.preSimilarity)}，Post Similarity ${formatRatio(vuln.postSimilarity)}。`,
    `风险级别：${vuln.status.severity.toUpperCase()}，可达性：${vuln.status.isReachable ? "可达" : "不可达"}。`,
    `处置建议：${statusGuidance(vuln)}`,
    `报告上下文：当前 APK 共识别 ${report.usedLibraries.length} 个组件，漏洞记录 ${report.vulnerabilities.length} 条。`,
    "提示：该解释由前端本地策略生成，后续可无缝替换为真实 LLM 流式接口。",
  ].join("\n");
}

export async function* streamCopilotText(text: string): AsyncGenerator<string> {
  const chunks = text.split("\n");
  for (const line of chunks) {
    for (const char of line + "\n") {
      await new Promise((resolve) => setTimeout(resolve, 12));
      yield char;
    }
    await new Promise((resolve) => setTimeout(resolve, 90));
  }
}
