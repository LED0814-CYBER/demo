import { Activity, Bot, FileBadge2, LayoutDashboard, ShieldCheck, UploadCloud } from "lucide-react";
import type { PropsWithChildren } from "react";
import { NavLink } from "react-router-dom";

import { useTaskStore } from "../../store/taskStore";

function NavItem({ to, label, icon }: { to: string; label: string; icon: JSX.Element }): JSX.Element {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition ${
          isActive
            ? "bg-cyan-500/15 text-cyan-100 ring-1 ring-cyan-400/40"
            : "text-slate-300 hover:bg-slate-800/70 hover:text-white"
        }`
      }
    >
      {icon}
      <span>{label}</span>
    </NavLink>
  );
}

export function AppShell({ children }: PropsWithChildren): JSX.Element {
  const currentTaskId = useTaskStore((state) => state.currentTaskId);

  return (
    <div className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(56,189,248,0.16),transparent_35%),radial-gradient(circle_at_85%_15%,rgba(248,113,113,0.13),transparent_30%),#030711] text-slate-100">
      <header className="sticky top-0 z-30 border-b border-slate-700/60 bg-slate-950/75 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-cyan-500/20 p-2 text-cyan-200 ring-1 ring-cyan-400/35">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-base font-semibold tracking-tight">Android Security Operations Console</p>
              <p className="text-xs text-slate-400">Competition Final Demo Frontend</p>
            </div>
          </div>

          <nav className="flex flex-wrap items-center gap-2">
            <NavItem to="/" label="Dashboard" icon={<LayoutDashboard className="h-4 w-4" />} />
            <NavItem to="/task/new" label="新建任务" icon={<UploadCloud className="h-4 w-4" />} />
            {currentTaskId && (
              <>
                <NavItem
                  to={`/task/${currentTaskId}/execution`}
                  label="执行监控"
                  icon={<Activity className="h-4 w-4" />}
                />
                <NavItem to={`/report/${currentTaskId}`} label="报告" icon={<FileBadge2 className="h-4 w-4" />} />
              </>
            )}
            <span className="inline-flex items-center gap-1 rounded-lg border border-violet-400/35 bg-violet-500/10 px-2.5 py-1 text-xs text-violet-100">
              <Bot className="h-3.5 w-3.5" />
              AI Copilot Ready
            </span>
          </nav>
        </div>
      </header>

      <main className="mx-auto w-full max-w-7xl px-6 py-6">{children}</main>
    </div>
  );
}
