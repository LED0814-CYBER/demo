import { Activity, BarChart3, Layers3, Shield } from "lucide-react";
import { Link } from "react-router-dom";

import { DashboardHero } from "../components/dashboard/DashboardHero";
import { RecentTasksPanel } from "../components/dashboard/RecentTasksPanel";
import { Panel } from "../components/common/Panel";
import { useTaskStore } from "../store/taskStore";

export function DashboardPage(): JSX.Element {
  const historyTaskIds = useTaskStore((state) => state.historyTaskIds);
  const reportsByTask = useTaskStore((state) => state.reportsByTask);
  const lastTaskId = useTaskStore((state) => state.lastTaskId);

  const reports = Object.values(reportsByTask);
  const totalVulns = reports.reduce((sum, report) => sum + report.vulnerabilities.length, 0);
  const totalLibraries = reports.reduce((sum, report) => sum + report.usedLibraries.length, 0);

  return (
    <div className="space-y-6">
      <DashboardHero />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Panel className="bg-slate-900/45" title="任务总数" right={<Activity className="h-4 w-4 text-cyan-300" />}>
          <p className="text-3xl font-semibold text-white">{historyTaskIds.length}</p>
          <p className="mt-1 text-xs text-slate-400">含报告与执行中的任务记录</p>
        </Panel>

        <Panel className="bg-slate-900/45" title="漏洞总记录" right={<Shield className="h-4 w-4 text-rose-300" />}>
          <p className="text-3xl font-semibold text-rose-100">{totalVulns}</p>
          <p className="mt-1 text-xs text-slate-400">用于答辩展示风险发现能力</p>
        </Panel>

        <Panel className="bg-slate-900/45" title="组件识别数" right={<Layers3 className="h-4 w-4 text-emerald-300" />}>
          <p className="text-3xl font-semibold text-emerald-100">{totalLibraries}</p>
          <p className="mt-1 text-xs text-slate-400">used_libraries 汇总统计</p>
        </Panel>

        <Panel className="bg-slate-900/45" title="展示入口" right={<BarChart3 className="h-4 w-4 text-violet-300" />}>
          {lastTaskId ? (
            <Link
              to={`/report/${lastTaskId}`}
              className="inline-flex rounded-lg border border-violet-500/50 bg-violet-500/10 px-3 py-2 text-xs text-violet-100"
            >
              打开最近报告
            </Link>
          ) : (
            <p className="text-sm text-slate-400">创建任务后自动生成入口</p>
          )}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <RecentTasksPanel historyTaskIds={historyTaskIds} />

        <Panel title="统计概览入口（答辩模式）">
          <p className="text-sm leading-7 text-slate-300">
            该区域可继续接入时间序列、任务通过率、组件风险分布等大屏指标。当前版本已完成最终版结构预留，不再与主流程耦合。
          </p>
          <div className="mt-4 rounded-xl border border-dashed border-slate-600/70 bg-slate-950/45 px-3 py-3 text-xs text-slate-400">
            下一步扩展建议：
            <br />
            1. 任务状态趋势图
            <br />
            2. 高风险 CVE TOP 榜
            <br />
            3. 组件来源占比图
          </div>
        </Panel>
      </div>
    </div>
  );
}
