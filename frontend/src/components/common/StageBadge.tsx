import type { TaskStage } from "../../types/domain";

const STAGE_THEME: Record<TaskStage, { label: string; className: string }> = {
  IDLE: {
    label: "待机",
    className: "border-slate-500/40 bg-slate-700/30 text-slate-200",
  },
  UPLOADING: {
    label: "上传中",
    className: "border-cyan-400/40 bg-cyan-500/15 text-cyan-200",
  },
  QUEUED: {
    label: "已排队",
    className: "border-blue-400/40 bg-blue-500/15 text-blue-200",
  },
  SCANNING: {
    label: "扫描中",
    className: "border-amber-400/40 bg-amber-500/15 text-amber-200",
  },
  REPORT_READY: {
    label: "报告就绪",
    className: "border-emerald-400/40 bg-emerald-500/15 text-emerald-200",
  },
  FAILED: {
    label: "失败",
    className: "border-rose-400/40 bg-rose-500/15 text-rose-200",
  },
};

export function StageBadge({ stage }: { stage: TaskStage }): JSX.Element {
  const theme = STAGE_THEME[stage];
  return <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${theme.className}`}>{theme.label}</span>;
}
