import type { PatchStatusSemantic } from "../../types/domain";

const colorMap: Record<PatchStatusSemantic["color"], string> = {
  danger: "border-rose-400/45 bg-rose-500/15 text-rose-200",
  warn: "border-amber-400/45 bg-amber-500/15 text-amber-200",
  safe: "border-emerald-400/45 bg-emerald-500/15 text-emerald-200",
  muted: "border-slate-400/45 bg-slate-500/15 text-slate-200",
  unknown: "border-cyan-400/45 bg-cyan-500/15 text-cyan-200",
};

export function PatchStatusBadge({ status }: { status: PatchStatusSemantic }): JSX.Element {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${colorMap[status.color]}`}>
      {status.label}
    </span>
  );
}
