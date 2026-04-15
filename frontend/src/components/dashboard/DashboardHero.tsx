import { ArrowRight, Radar, ShieldAlert, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";

import { Panel } from "../common/Panel";

export function DashboardHero(): JSX.Element {
  return (
    <Panel className="relative overflow-hidden border-cyan-900/60 bg-[linear-gradient(120deg,rgba(6,182,212,0.17),rgba(30,41,59,0.55))]">
      <div className="absolute -right-24 -top-24 h-64 w-64 rounded-full bg-cyan-400/10 blur-3xl" />
      <div className="absolute -bottom-20 -left-20 h-56 w-56 rounded-full bg-rose-400/10 blur-3xl" />

      <div className="relative grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
        <div>
          <p className="text-xs uppercase tracking-[0.25em] text-cyan-200/80">Security Competition Final</p>
          <h1 className="mt-3 text-3xl font-semibold leading-tight text-white lg:text-4xl">
            Android 漏洞自动验证
            <span className="block text-cyan-200">SOC 竞赛展示前端</span>
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-200/90">
            统一接入 APK 上传、实时执行日志、漏洞补丁证据链、SBOM 拓扑图与 AI 副屏解释，面向答辩演示与后续扩展。
          </p>

          <div className="mt-6 flex flex-wrap gap-3">
            <Link
              to="/task/new"
              className="inline-flex items-center gap-2 rounded-xl bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300"
            >
              开始新任务
              <ArrowRight className="h-4 w-4" />
            </Link>
            <span className="inline-flex items-center gap-2 rounded-xl border border-slate-600/70 bg-slate-950/50 px-3 py-2 text-xs text-slate-200">
              <Radar className="h-4 w-4 text-cyan-300" />
              实时日志 + 自动恢复
            </span>
            <span className="inline-flex items-center gap-2 rounded-xl border border-slate-600/70 bg-slate-950/50 px-3 py-2 text-xs text-slate-200">
              <ShieldAlert className="h-4 w-4 text-amber-300" />
              Patch 语义适配
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 text-sm">
          {[
            { icon: <ShieldCheck className="h-4 w-4 text-emerald-300" />, title: "协议兼容", desc: "保持 /api/upload /api/analyze /api/report /api/logs" },
            { icon: <Radar className="h-4 w-4 text-cyan-300" />, title: "执行监控", desc: "WebSocket 断线重连 + 轮询降级" },
            { icon: <ShieldAlert className="h-4 w-4 text-orange-300" />, title: "证据面板", desc: "相似度对比 + 一句话结论" },
            { icon: <ArrowRight className="h-4 w-4 text-violet-300" />, title: "AI 副屏", desc: "本地流式解释，预留 LLM 接口" },
          ].map((item) => (
            <article key={item.title} className="rounded-xl border border-slate-600/60 bg-slate-950/55 p-3">
              <div className="inline-flex items-center gap-2 text-sm font-semibold text-white">
                {item.icon}
                {item.title}
              </div>
              <p className="mt-2 text-xs leading-6 text-slate-300">{item.desc}</p>
            </article>
          ))}
        </div>
      </div>
    </Panel>
  );
}
