import type { PropsWithChildren, ReactNode } from "react";

interface PanelProps extends PropsWithChildren {
  title?: ReactNode;
  right?: ReactNode;
  className?: string;
}

export function Panel({ title, right, className = "", children }: PanelProps): JSX.Element {
  return (
    <section className={`rounded-2xl border border-slate-700/70 bg-slate-900/55 p-5 shadow-[0_0_0_1px_rgba(70,85,120,0.2)] ${className}`}>
      {(title || right) && (
        <header className="mb-4 flex items-center justify-between gap-4">
          <div className="text-sm font-semibold tracking-wide text-slate-100">{title}</div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}
