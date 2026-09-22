import { useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtTime, SEVERITY_STYLE } from "@/lib/format";
import { Play, Zap, Clock3 } from "lucide-react";
import { toast } from "sonner";

export default function Analysis() {
  const utils = trpc.useUtils();
  const { data } = trpc.analysis.rules.useQuery();
  const runs = trpc.analysis.runs.useQuery();
  const [running, setRunning] = useState<string | null>(null);
  const [runningAll, setRunningAll] = useState(false);

  const runOne = trpc.analysis.run.useMutation({
    onSuccess: (r) => {
      toast.success(`分析完成：扫描 ${r.scanned} 条会话，产出 ${r.alerts} 条告警（${r.durationMs}ms）`);
      utils.analysis.rules.invalidate();
      utils.analysis.runs.invalidate();
      utils.dashboard.overview.invalidate();
      setRunning(null);
    },
    onError: (e) => { toast.error(`分析失败：${e.message}`); setRunning(null); },
  });
  const runAll = trpc.analysis.runAll.useMutation({
    onSuccess: (rs) => {
      const total = rs.reduce((s, r) => s + r.alerts, 0);
      toast.success(`全量分析完成：${rs.length} 个场景共产出 ${total} 条告警`);
      utils.analysis.rules.invalidate();
      utils.analysis.runs.invalidate();
      utils.dashboard.overview.invalidate();
      setRunningAll(false);
    },
    onError: (e) => { toast.error(`分析失败：${e.message}`); setRunningAll(false); },
  });

  if (!data) return <div className="py-20 text-center text-sm text-neutral-500">数据加载中…</div>;

  const cats = Object.entries(data.categories) as Array<[string, { label: string; en: string; desc: string }]>;

  return (
    <div>
      <PageHeader
        title="行为关联分析"
        en="BEHAVIOR CORRELATION"
        desc={`${data.rules.length} 个关联分析场景，基于会话元数据做跨会话聚合、周期性与基线计算`}
        extra={
          <button
            onClick={() => { setRunningAll(true); runAll.mutate(); }}
            disabled={runningAll || running !== null}
            className="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium text-black transition-opacity disabled:opacity-50"
            style={{ background: "var(--mint)" }}
          >
            <Zap className="h-4 w-4" />
            {runningAll ? "全量分析中…" : "运行全部分析"}
          </button>
        }
      />

      <div className="space-y-8">
        {cats.map(([code, meta]) => {
          const rules = data.rules.filter((r) => r.category === code);
          return (
            <section key={code}>
              <div className="mb-3 flex items-baseline gap-3">
                <h2 className="font-display text-base font-semibold">{meta.label}</h2>
                <span className="micro-label">{meta.en}</span>
                <span className="text-xs text-neutral-500">{meta.desc}</span>
                <span className="num ml-auto text-xs text-neutral-500">{rules.length} 个场景</span>
              </div>
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                {rules.map((r) => {
                  const sev = SEVERITY_STYLE[r.severity];
                  const isRunning = running === r.code;
                  return (
                    <div key={r.code} className="panel flex flex-col p-5">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-display text-sm font-semibold">{r.name}</span>
                            <span className="rounded px-1.5 py-0.5 text-[10px] font-medium" style={{ background: sev?.bg, color: sev?.color }}>{sev?.label}</span>
                          </div>
                          <div className="num mt-0.5 text-[11px] text-neutral-600">{r.code}</div>
                        </div>
                        <button
                          onClick={() => { setRunning(r.code); runOne.mutate({ ruleCode: r.code }); }}
                          disabled={isRunning || runningAll || (running !== null && !isRunning)}
                          className="flex shrink-0 items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs transition-colors disabled:opacity-40"
                          style={{ borderColor: "var(--mint)", color: "var(--mint)" }}
                        >
                          <Play className="h-3 w-3" />
                          {isRunning ? "分析中…" : "运行分析"}
                        </button>
                      </div>
                      <p className="mt-2.5 text-xs leading-5 text-neutral-400">{r.desc}</p>
                      <div className="mt-3 rounded-md border p-3 text-xs leading-5 text-neutral-500" style={{ borderColor: "var(--line)", background: "var(--surface-2)" }}>
                        <span className="micro-label mr-2">LOGIC</span>{r.logic}
                      </div>
                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {r.fields.map((f) => (
                          <span key={f} className="num rounded bg-white/5 px-1.5 py-0.5 text-[10px] text-neutral-400">{f}</span>
                        ))}
                      </div>
                      <div className="mt-4 flex items-center gap-4 border-t pt-3 text-[11px] text-neutral-500" style={{ borderColor: "var(--line)" }}>
                        <span>告警 <span className="num" style={{ color: r.alertCount > 0 ? "var(--orange, #ff8c42)" : undefined }}>{r.alertCount}</span></span>
                        <span>运行 <span className="num">{r.runCount}</span> 次</span>
                        {r.lastRunAt && (
                          <span className="ml-auto flex items-center gap-1">
                            <Clock3 className="h-3 w-3" />
                            <span className="num">{fmtTime(r.lastRunAt)}</span>
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          );
        })}
      </div>

      <section className="panel mt-8 p-5">
        <div className="micro-label">RUN HISTORY</div>
        <div className="mt-1 mb-3 text-sm font-medium">分析任务运行记录</div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-neutral-500">
              <th className="py-2 pr-3 font-medium">规则</th>
              <th className="py-2 pr-3 font-medium">状态</th>
              <th className="py-2 pr-3 font-medium text-right">扫描会话</th>
              <th className="py-2 pr-3 font-medium text-right">产出告警</th>
              <th className="py-2 pr-3 font-medium text-right">耗时</th>
              <th className="py-2 font-medium text-right">开始时间</th>
            </tr>
          </thead>
          <tbody>
            {runs.data?.map((r) => (
              <tr key={r.id} className="border-t text-xs" style={{ borderColor: "var(--line)" }}>
                <td className="num py-2 pr-3" style={{ color: "var(--mint)" }}>{r.ruleCode}</td>
                <td className="py-2 pr-3">
                  <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: r.status === "success" ? "var(--mint-dim)" : "rgba(255,68,68,0.12)", color: r.status === "success" ? "var(--mint)" : "#ff4444" }}>
                    {r.status === "success" ? "成功" : r.status}
                  </span>
                </td>
                <td className="num py-2 pr-3 text-right text-neutral-300">{r.sessionsScanned.toLocaleString()}</td>
                <td className="num py-2 pr-3 text-right text-neutral-300">{r.alertsGenerated}</td>
                <td className="num py-2 pr-3 text-right text-neutral-400">{r.durationMs}ms</td>
                <td className="num py-2 text-right text-neutral-500">{fmtTime(r.startedAt)}</td>
              </tr>
            ))}
            {runs.data?.length === 0 && (
              <tr><td colSpan={6} className="py-8 text-center text-xs text-neutral-500">尚未运行过分析任务</td></tr>
            )}
          </tbody>
        </table>
      </section>
    </div>
  );
}
