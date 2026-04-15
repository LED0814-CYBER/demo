import { useEffect, useRef } from "react";

import type { LogEntry } from "../../types/domain";

function colorBySource(source: LogEntry["source"]): string {
  if (source === "stderr") return "text-rose-200";
  if (source === "meta") return "text-cyan-200";
  if (source === "socket") return "text-amber-200";
  if (source === "system") return "text-slate-200";
  return "text-emerald-200";
}

export function LogTerminal({ logs }: { logs: LogEntry[] }): JSX.Element {
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (ref.current) {
      ref.current.scrollTop = ref.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div
      ref={ref}
      className="h-[520px] overflow-y-auto rounded-xl border border-emerald-900/70 bg-black/80 p-4 font-mono text-xs leading-6"
    >
      {logs.map((entry) => (
        <div key={entry.id} className={`animate-terminal-fade break-words whitespace-pre-wrap ${colorBySource(entry.source)}`}>
          <span className="mr-2 text-emerald-700">$</span>
          {entry.message}
        </div>
      ))}
    </div>
  );
}
