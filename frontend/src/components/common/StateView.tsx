import { AlertTriangle, Loader2 } from "lucide-react";

export function LoadingView({ text }: { text: string }): JSX.Element {
  return (
    <div className="flex min-h-[220px] items-center justify-center rounded-xl border border-slate-700/60 bg-slate-900/40 text-slate-300">
      <span className="inline-flex items-center gap-2 text-sm">
        <Loader2 className="h-4 w-4 animate-spin" />
        {text}
      </span>
    </div>
  );
}

export function ErrorView({ text }: { text: string }): JSX.Element {
  return (
    <div className="flex min-h-[220px] items-center justify-center rounded-xl border border-rose-700/50 bg-rose-950/30 text-rose-100">
      <span className="inline-flex items-center gap-2 text-sm">
        <AlertTriangle className="h-4 w-4" />
        {text}
      </span>
    </div>
  );
}
