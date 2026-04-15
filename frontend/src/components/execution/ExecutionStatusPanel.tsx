import { AlertTriangle, RotateCcw, WifiOff } from "lucide-react";

import type { TaskStage, WsConnectionState } from "../../types/domain";
import { StageBadge } from "../common/StageBadge";

interface ExecutionStatusPanelProps {
  taskId: string;
  stage: TaskStage;
  wsState: WsConnectionState;
  isPollingFallback: boolean;
  errorMessage: string | null;
  onReconnect: () => void;
}

function wsLabel(wsState: WsConnectionState): { label: string; className: string } {
  switch (wsState) {
    case "CONNECTED":
      return { label: "WS 已连接", className: "text-emerald-200" };
    case "CONNECTING":
      return { label: "WS 连接中", className: "text-cyan-200" };
    case "RECONNECTING":
      return { label: "WS 重连中", className: "text-amber-200" };
    case "DEGRADED":
      return { label: "降级模式", className: "text-violet-200" };
    case "FAILED":
      return { label: "连接失败", className: "text-rose-200" };
    default:
      return { label: "未连接", className: "text-slate-300" };
  }
}

export function ExecutionStatusPanel({
  taskId,
  stage,
  wsState,
  isPollingFallback,
  errorMessage,
  onReconnect,
}: ExecutionStatusPanelProps): JSX.Element {
  const ws = wsLabel(wsState);

  return (
    <div className="space-y-4 rounded-2xl border border-slate-700/70 bg-slate-900/50 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="text-xs text-slate-400">当前任务</p>
          <p className="font-mono text-sm text-slate-100">{taskId}</p>
        </div>
        <StageBadge stage={stage} />
      </div>

      <div className="rounded-xl border border-slate-700/70 bg-slate-950/60 px-3 py-2 text-sm">
        <p className={`font-medium ${ws.className}`}>{ws.label}</p>
        {isPollingFallback && (
          <p className="mt-1 inline-flex items-center gap-1 text-xs text-violet-200">
            <WifiOff className="h-3.5 w-3.5" />
            WebSocket 重连失败，已启用短轮询拉取报告。
          </p>
        )}
      </div>

      {errorMessage && (
        <div className="rounded-xl border border-rose-700/60 bg-rose-900/30 px-3 py-2 text-sm text-rose-100">
          <p className="inline-flex items-center gap-1">
            <AlertTriangle className="h-4 w-4" />
            {errorMessage}
          </p>
        </div>
      )}

      <button
        type="button"
        onClick={onReconnect}
        className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/55 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-100 transition hover:bg-cyan-500/20"
      >
        <RotateCcw className="h-3.5 w-3.5" />
        手动重连执行通道
      </button>
    </div>
  );
}
