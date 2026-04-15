import { ArrowDownWideNarrow } from "lucide-react";

import type { UsedLibraryModel } from "../../types/domain";

interface LibrariesTableProps {
  libraries: UsedLibraryModel[];
  selectedLibraryId: string | null;
  onSelect: (libraryId: string) => void;
}

function riskColor(vulnCount: number): string {
  if (vulnCount >= 2) return "text-rose-200";
  if (vulnCount === 1) return "text-amber-200";
  return "text-emerald-200";
}

export function LibrariesTable({ libraries, selectedLibraryId, onSelect }: LibrariesTableProps): JSX.Element {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-700/70">
      <div className="flex items-center justify-between border-b border-slate-700/70 bg-slate-900 px-4 py-3">
        <p className="text-sm font-semibold text-slate-100">Used Libraries（SBOM）</p>
        <span className="inline-flex items-center gap-1 text-xs text-slate-400">
          <ArrowDownWideNarrow className="h-3.5 w-3.5" />
          按漏洞数量/置信度排序
        </span>
      </div>

      <div className="max-h-[320px] overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 z-10 bg-slate-900/95 text-slate-300">
            <tr>
              <th className="px-3 py-2">Group</th>
              <th className="px-3 py-2">Artifact</th>
              <th className="px-3 py-2">Version</th>
              <th className="px-3 py-2">Confidence</th>
              <th className="px-3 py-2">漏洞数</th>
            </tr>
          </thead>
          <tbody>
            {libraries.map((lib) => {
              const selected = selectedLibraryId === lib.id;
              return (
                <tr
                  key={lib.id}
                  className={`cursor-pointer border-t border-slate-800/80 transition ${
                    selected ? "bg-cyan-500/10" : "bg-slate-950/50 hover:bg-slate-800/55"
                  }`}
                  onClick={() => onSelect(lib.id)}
                >
                  <td className="px-3 py-2 text-slate-200">{lib.group}</td>
                  <td className="px-3 py-2 text-slate-100">{lib.artifact}</td>
                  <td className="px-3 py-2 text-slate-300">{lib.version}</td>
                  <td className="px-3 py-2 text-slate-300">{(lib.confidence * 100).toFixed(1)}%</td>
                  <td className={`px-3 py-2 font-semibold ${riskColor(lib.vulnerabilityCount)}`}>{lib.vulnerabilityCount}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
