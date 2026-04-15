import type { ReportModel } from "../../types/domain";

const cardTheme = {
  highRisk: "border-rose-600/45 bg-rose-500/10 text-rose-100",
  mediumRisk: "border-amber-600/45 bg-amber-500/10 text-amber-100",
  safeCount: "border-emerald-600/45 bg-emerald-500/10 text-emerald-100",
  unknownCount: "border-cyan-600/45 bg-cyan-500/10 text-cyan-100",
  total: "border-slate-600/70 bg-slate-700/30 text-slate-100",
};

export function ReportSummaryCards({ report }: { report: ReportModel }): JSX.Element {
  const cards = [
    { key: "highRisk", label: "高风险", value: report.summary.highRisk },
    { key: "mediumRisk", label: "待复核", value: report.summary.mediumRisk },
    { key: "safeCount", label: "安全/已修复", value: report.summary.safeCount },
    { key: "unknownCount", label: "不确定状态", value: report.summary.unknownCount },
    { key: "total", label: "漏洞总数", value: report.summary.total },
  ] as const;

  return (
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
      {cards.map((card) => (
        <article key={card.key} className={`rounded-xl border px-4 py-3 ${cardTheme[card.key]}`}>
          <p className="text-xs opacity-85">{card.label}</p>
          <p className="mt-1 text-2xl font-semibold">{card.value}</p>
        </article>
      ))}
    </div>
  );
}
