import { Bot, Sparkles } from "lucide-react";

import type { ReportModel, VulnerabilityModel } from "../../types/domain";
import { useCopilotStream } from "../../hooks/useCopilotStream";

export function CopilotPanel({
  vulnerability,
  report,
}: {
  vulnerability: VulnerabilityModel | null;
  report: ReportModel | null;
}): JSX.Element {
  const streamText = useCopilotStream(vulnerability, report);

  return (
    <div className="rounded-xl border border-violet-500/35 bg-[linear-gradient(145deg,rgba(124,58,237,0.2),rgba(15,23,42,0.85))] p-4">
      <div className="flex items-center justify-between">
        <p className="inline-flex items-center gap-2 text-sm font-semibold text-violet-100">
          <Bot className="h-4 w-4" />
          AI Analysis Copilot
        </p>
        <span className="inline-flex items-center gap-1 text-xs text-violet-200/90">
          <Sparkles className="h-3.5 w-3.5" />
          Streaming Demo
        </span>
      </div>

      <pre className="mt-3 min-h-[220px] whitespace-pre-wrap rounded-lg border border-violet-400/20 bg-black/35 p-3 font-mono text-xs leading-6 text-violet-100">
        {streamText}
      </pre>
    </div>
  );
}
