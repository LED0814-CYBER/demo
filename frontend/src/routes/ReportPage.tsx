import { FileWarning, FlaskConical } from "lucide-react";
import { useEffect, useMemo } from "react";
import { Link, useParams } from "react-router-dom";

import { Panel } from "../components/common/Panel";
import { ErrorView, LoadingView } from "../components/common/StateView";
import { CopilotPanel } from "../components/report/CopilotPanel";
import { EvidencePanel } from "../components/report/EvidencePanel";
import { LibrariesTable } from "../components/report/LibrariesTable";
import { ReportSummaryCards } from "../components/report/ReportSummaryCards";
import { SbomGraph } from "../components/report/SbomGraph";
import { VulnerabilityTable } from "../components/report/VulnerabilityTable";
import { useTaskStore } from "../store/taskStore";
import { formatBytes, shortHash } from "../utils/format";

export function ReportPage(): JSX.Element {
  const params = useParams();
  const taskId = params.taskId;

  const ensureReport = useTaskStore((state) => state.ensureReport);
  const reportsByTask = useTaskStore((state) => state.reportsByTask);
  const errorMessage = useTaskStore((state) => state.errorMessage);
  const activeVulnerabilityId = useTaskStore((state) => state.activeVulnerabilityId);
  const selectedLibraryId = useTaskStore((state) => state.selectedLibraryId);
  const setActiveVulnerability = useTaskStore((state) => state.setActiveVulnerability);
  const setSelectedLibrary = useTaskStore((state) => state.setSelectedLibrary);

  const report = taskId ? reportsByTask[taskId] || null : null;

  useEffect(() => {
    if (!taskId) return;
    if (reportsByTask[taskId]) return;
    void ensureReport(taskId, false);
  }, [taskId, reportsByTask, ensureReport]);

  useEffect(() => {
    if (!report) return;
    if (!activeVulnerabilityId && report.vulnerabilities[0]) {
      setActiveVulnerability(report.vulnerabilities[0].id);
    }
    if (!selectedLibraryId && report.usedLibraries[0]) {
      setSelectedLibrary(report.usedLibraries[0].id);
    }
  }, [report, activeVulnerabilityId, selectedLibraryId, setActiveVulnerability, setSelectedLibrary]);

  const selectedLibrary = useMemo(() => {
    if (!report || !selectedLibraryId) return null;
    return report.usedLibraries.find((lib) => lib.id === selectedLibraryId) || null;
  }, [report, selectedLibraryId]);

  const visibleVulnerabilities = useMemo(() => {
    if (!report) return [];
    if (!selectedLibrary) return report.vulnerabilities;
    return report.vulnerabilities.filter((vuln) => vuln.library === selectedLibrary.libraryName);
  }, [report, selectedLibrary]);

  const activeVulnerability = useMemo(() => {
    if (!report || !activeVulnerabilityId) return null;
    return report.vulnerabilities.find((v) => v.id === activeVulnerabilityId) || null;
  }, [report, activeVulnerabilityId]);

  if (!taskId) {
    return <ErrorView text="缺少 taskId，请从执行页或首页进入报告。" />;
  }

  if (!report && !errorMessage) {
    return <LoadingView text="正在加载报告数据..." />;
  }

  if (!report && errorMessage) {
    return (
      <div className="space-y-4">
        <ErrorView text={errorMessage} />
        <Link
          to={`/task/${taskId}/execution`}
          className="inline-flex rounded-lg border border-cyan-500/45 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100"
        >
          返回执行页重试
        </Link>
      </div>
    );
  }

  if (!report) return <LoadingView text="报告加载中..." />;

  return (
    <div className="space-y-6">
      <ReportSummaryCards report={report} />

      <Panel title="APK 基础信息" right={<FlaskConical className="h-4 w-4 text-cyan-300" />}>
        <div className="grid gap-3 text-sm md:grid-cols-3">
          <div className="rounded-lg border border-slate-700/70 bg-slate-950/60 px-3 py-2">
            <p className="text-xs text-slate-400">名称</p>
            <p className="mt-1 text-slate-100">{report.apkInfo.name}</p>
          </div>
          <div className="rounded-lg border border-slate-700/70 bg-slate-950/60 px-3 py-2">
            <p className="text-xs text-slate-400">SHA256</p>
            <p className="mt-1 font-mono text-cyan-200">{shortHash(report.apkInfo.sha256)}</p>
          </div>
          <div className="rounded-lg border border-slate-700/70 bg-slate-950/60 px-3 py-2">
            <p className="text-xs text-slate-400">大小</p>
            <p className="mt-1 text-slate-100">{formatBytes(report.apkInfo.size)}</p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-6 xl:grid-cols-[0.58fr_0.42fr]">
        <Panel title="SBOM 拓扑图（可演示）">
          <SbomGraph
            apkName={report.apkInfo.name}
            libraries={report.usedLibraries}
            selectedLibraryId={selectedLibraryId}
            onSelectLibrary={(id) => setSelectedLibrary(id)}
          />
          <p className="mt-3 text-xs text-slate-400">
            中心节点为 APK，外围节点为 third-party libraries。危险组件以暖色高亮，点击节点联动下方漏洞与右侧证据区。
          </p>
        </Panel>

        <Panel title="组件清单 / used_libraries" right={<FileWarning className="h-4 w-4 text-amber-300" />}>
          <LibrariesTable
            libraries={report.usedLibraries}
            selectedLibraryId={selectedLibraryId}
            onSelect={(id) => {
              setSelectedLibrary(id);
              const first = report.vulnerabilities.find((v) => {
                const lib = report.usedLibraries.find((item) => item.id === id);
                return lib ? v.library === lib.libraryName : false;
              });
              if (first) setActiveVulnerability(first.id);
            }}
          />
        </Panel>
      </div>

      <div className="grid gap-6 xl:grid-cols-[0.62fr_0.38fr]">
        <Panel title="漏洞明细 / vulnerabilities">
          <VulnerabilityTable
            vulnerabilities={visibleVulnerabilities}
            activeId={activeVulnerabilityId}
            onSelect={(id) => setActiveVulnerability(id)}
          />
        </Panel>

        <div className="space-y-4">
          <EvidencePanel vulnerability={activeVulnerability} />
          <CopilotPanel vulnerability={activeVulnerability} report={report} />
        </div>
      </div>
    </div>
  );
}
