import { GaugeCircle } from "lucide-react";

import { PatchStatusBadge } from "../common/PatchStatusBadge";
import type { VulnerabilityModel } from "../../types/domain";
import { clamp01, formatRatio } from "../../utils/format";

function SimilarityBar({ label, value, colorClass }: { label: string; value: number | null; colorClass: string }): JSX.Element {
  const ratio = clamp01(value);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-slate-300">
        <span>{label}</span>
        <span>{formatRatio(value)}</span>
      </div>
      <div className="h-2 rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${colorClass}`} style={{ width: `${ratio * 100}%` }} />
      </div>
    </div>
  );
}

export function EvidencePanel({ vulnerability }: { vulnerability: VulnerabilityModel | null }): JSX.Element {
  if (!vulnerability) {
    return (
      <div className="rounded-xl border border-slate-700/70 bg-slate-900/45 p-4 text-sm text-slate-400">
        选择漏洞后将在此展示补丁证据与结论。
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-700/70 bg-slate-900/45 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs text-slate-400">Evidence Panel</p>
          <p className="text-sm font-semibold text-slate-100">{vulnerability.cveId}</p>
        </div>
        <PatchStatusBadge status={vulnerability.status} />
      </div>

      <div className="mt-4 space-y-3">
        <SimilarityBar label="Pre Similarity" value={vulnerability.preSimilarity} colorClass="bg-rose-500" />
        <SimilarityBar label="Post Similarity" value={vulnerability.postSimilarity} colorClass="bg-emerald-500" />
      </div>

      <div className="mt-4 rounded-lg border border-slate-700/70 bg-slate-950/65 p-3 text-xs text-slate-200">
        <p className="inline-flex items-center gap-1 font-semibold text-slate-100">
          <GaugeCircle className="h-4 w-4 text-cyan-300" />
          一句话结论
        </p>
        <p className="mt-2 leading-6">{vulnerability.status.conclusion}</p>
      </div>

      <div className="mt-4 rounded-lg border border-slate-800 bg-black/50 p-3 text-xs text-slate-400">
        <p className="font-semibold text-slate-300">原始字段（调试）</p>
        <p className="mt-1">raw.status: {String(vulnerability.raw.status)}</p>
        <p>raw.pre_similarity: {String(vulnerability.raw.pre_similarity)}</p>
        <p>raw.post_similarity: {String(vulnerability.raw.post_similarity)}</p>
      </div>
    </div>
  );
}
