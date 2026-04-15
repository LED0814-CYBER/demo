import { ArrowRightCircle, FileText } from "lucide-react";
import { useEffect } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { ExecutionStatusPanel } from "../components/execution/ExecutionStatusPanel";
import { LogTerminal } from "../components/execution/LogTerminal";
import { Panel } from "../components/common/Panel";
import { StageBadge } from "../components/common/StageBadge";
import { useTaskBootstrap } from "../hooks/useTaskBootstrap";
import { useTaskStore } from "../store/taskStore";

export function ExecutionPage(): JSX.Element {
  const navigate = useNavigate();
  const params = useParams();
  const taskId = params.taskId;

  useTaskBootstrap(taskId);

  const logs = useTaskStore((state) => state.logs);
  const taskStage = useTaskStore((state) => state.taskStage);
  const wsState = useTaskStore((state) => state.wsState);
  const isPollingFallback = useTaskStore((state) => state.isPollingFallback);
  const errorMessage = useTaskStore((state) => state.errorMessage);
  const connectExecution = useTaskStore((state) => state.connectExecution);

  useEffect(() => {
    if (taskStage !== "REPORT_READY" || !taskId) return;
    const timer = window.setTimeout(() => {
      navigate(`/report/${taskId}`);
    }, 1200);
    return () => window.clearTimeout(timer);
  }, [taskStage, taskId, navigate]);

  if (!taskId) {
    return (
      <Panel title="执行监控">
        <p className="text-sm text-slate-300">任务 ID 缺失，请先前往新建任务页。</p>
        <Link
          to="/task/new"
          className="mt-4 inline-flex rounded-lg border border-cyan-500/50 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100"
        >
          去新建任务
        </Link>
      </Panel>
    );
  }

  return (
    <div className="grid gap-6 xl:grid-cols-[0.34fr_0.66fr]">
      <div className="space-y-4">
        <ExecutionStatusPanel
          taskId={taskId}
          stage={taskStage}
          wsState={wsState}
          isPollingFallback={isPollingFallback}
          errorMessage={errorMessage}
          onReconnect={() => {
            void connectExecution(taskId);
          }}
        />

        <Panel title="流程状态">
          <div className="space-y-3 text-sm text-slate-300">
            <div className="flex items-center justify-between">
              <span>任务阶段</span>
              <StageBadge stage={taskStage} />
            </div>
            <div className="flex items-center justify-between">
              <span>日志条数</span>
              <span>{logs.length}</span>
            </div>
            <div className="flex items-center justify-between">
              <span>执行页恢复</span>
              <span className="text-emerald-200">URL + localStorage</span>
            </div>
          </div>
        </Panel>

        <div className="flex flex-wrap gap-2">
          <Link
            to={`/report/${taskId}`}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-500/60 bg-slate-700/35 px-3 py-2 text-xs text-slate-100"
          >
            <FileText className="h-3.5 w-3.5" />
            立即查看报告
          </Link>
          <button
            type="button"
            onClick={() => {
              void connectExecution(taskId);
            }}
            className="inline-flex items-center gap-1 rounded-lg border border-cyan-500/55 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100"
          >
            <ArrowRightCircle className="h-3.5 w-3.5" />
            重建监控连接
          </button>
        </div>
      </div>

      <Panel title="实时终端" className="border-emerald-900/40 bg-[#020902]">
        <LogTerminal logs={logs} />
      </Panel>
    </div>
  );
}
