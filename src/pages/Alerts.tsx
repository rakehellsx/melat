import { useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtTime, SEVERITY_STYLE, CATEGORY_STYLE } from "@/lib/format";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { ChevronLeft, ChevronRight, Check, X } from "lucide-react";
import { toast } from "sonner";
interface Alert {
  id: number; ruleCode: string; ruleName: string; category: string; severity: string;
  title: string; srcIp: string | null; dstIp: string | null; score: number;
  evidence: Record<string, unknown>; relatedSessions: string[];
  status: string; runId: number | null; createdAt: string;
}

const SEVS = ["", "critical", "high", "medium", "low"] as const;
const CATS = ["", "attack", "c2", "data", "baseline", "custom"] as const;
const STATUS_LABEL: Record<string, { label: string; color: string }> = {
  open: { label: "待处置", color: "#ff4444" },
  confirmed: { label: "已确认", color: "#ffd166" },
  dismissed: { label: "已忽略", color: "#6b7280" },
};

function EvidenceValue({ v }: { v: unknown }) {
  if (Array.isArray(v)) {
    if (v.length > 0 && typeof v[0] === "object") {
      return <pre className="num whitespace-pre-wrap text-[11px] leading-4 text-neutral-300">{JSON.stringify(v, null, 1)}</pre>;
    }
    return <span className="num text-[11px] text-neutral-300">{v.join("、")}</span>;
  }
  if (typeof v === "object" && v !== null) {
    return (
      <span className="flex flex-wrap gap-1.5">
        {Object.entries(v as Record<string, unknown>).map(([k, val]) => (
          <span key={k} className="rounded bg-white/5 px-1.5 py-0.5 text-[10px] text-neutral-300">{k}: {String(val)}</span>
        ))}
      </span>
    );
  }
  return <span className="num text-[11px] text-neutral-200">{String(v)}</span>;
}

export default function Alerts() {
  const utils = trpc.useUtils();
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [selected, setSelected] = useState<Alert | null>(null);

  const { data } = trpc.alert.list.useQuery({
    page, pageSize: 15,
    severity: severity || undefined, category: category || undefined,
  });
  const update = trpc.alert.updateStatus.useMutation({
    onSuccess: () => {
      toast.success("告警状态已更新");
      utils.alert.list.invalidate();
      utils.dashboard.overview.invalidate();
    },
  });

  const totalPages = data ? Math.max(1, Math.ceil(data.total / 15)) : 1;
  const selBtn = (a: boolean) =>
    a ? { background: "var(--mint-dim)", color: "var(--mint)" } : { color: "#9ca3af", background: "var(--surface)" };

  return (
    <div>
      <PageHeader title="告警中心" en="ALERT CENTER" desc="行为关联分析产出的全部告警，点击可查看量化证据与关联会话" />

      <div className="mb-4 flex flex-wrap gap-1.5">
        {SEVS.map((s) => (
          <button key={s || "all"} onClick={() => { setSeverity(s); setPage(1); }} className="rounded-md px-3 py-1.5 text-xs" style={selBtn(severity === s)}>
            {s ? SEVERITY_STYLE[s].label : "全部级别"}
          </button>
        ))}
        <span className="mx-2 w-px self-stretch" style={{ background: "var(--line)" }} />
        {CATS.map((c) => (
          <button key={c || "all"} onClick={() => { setCategory(c); setPage(1); }} className="rounded-md px-3 py-1.5 text-xs" style={selBtn(category === c)}>
            {c ? CATEGORY_STYLE[c].label : "全部类别"}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {data?.rows.map((a) => {
          const sev = SEVERITY_STYLE[a.severity];
          const st = STATUS_LABEL[a.status];
          return (
            <div
              key={a.id}
              onClick={() => setSelected(a)}
              className="panel flex cursor-pointer items-center gap-4 px-5 py-3.5 transition-colors hover:border-neutral-600"
            >
              <span className="w-12 shrink-0 rounded px-2 py-1 text-center text-[11px] font-medium" style={{ background: sev?.bg, color: sev?.color }}>
                {sev?.label}
              </span>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm text-neutral-100">{a.title}</div>
                <div className="mt-1 flex items-center gap-3 text-[11px] text-neutral-500">
                  <span style={{ color: CATEGORY_STYLE[a.category]?.color }}>{CATEGORY_STYLE[a.category]?.label}</span>
                  <span className="num">{a.ruleCode}</span>
                  {a.srcIp && <span className="num">源 {a.srcIp}</span>}
                  {a.dstIp && <span className="num">目的 {a.dstIp}</span>}
                </div>
              </div>
              <div className="num shrink-0 text-right">
                <div className="text-lg font-semibold" style={{ color: sev?.color }}>{a.score}</div>
                <div className="text-[10px] text-neutral-600">风险分</div>
              </div>
              <div className="w-16 shrink-0 text-right">
                <span className="text-[11px]" style={{ color: st?.color }}>{st?.label}</span>
                <div className="num mt-1 text-[10px] text-neutral-600">{fmtTime(a.createdAt).slice(5, 16)}</div>
              </div>
            </div>
          );
        })}
        {data?.rows.length === 0 && (
          <div className="panel py-16 text-center text-sm text-neutral-500">暂无告警 —— 请先到「行为关联分析」运行分析任务</div>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-neutral-400">
        <span className="num text-xs">共 {data?.total ?? 0} 条告警 · 第 {page}/{totalPages} 页</span>
        <div className="flex gap-2">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="rounded-md border p-1.5 disabled:opacity-30" style={{ borderColor: "var(--line)" }}>
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="rounded-md border p-1.5 disabled:opacity-30" style={{ borderColor: "var(--line)" }}>
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent side="right" className="w-[640px] overflow-y-auto border-l sm:max-w-[640px]" style={{ background: "var(--surface)", borderColor: "var(--line)" }}>
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="flex items-center gap-2 text-base leading-6">
                  <span className="shrink-0 rounded px-2 py-0.5 text-[11px]" style={{ background: SEVERITY_STYLE[selected.severity]?.bg, color: SEVERITY_STYLE[selected.severity]?.color }}>
                    {SEVERITY_STYLE[selected.severity]?.label}
                  </span>
                  {selected.ruleName}
                </SheetTitle>
              </SheetHeader>
              <div className="mt-4 space-y-5 pb-10">
                <p className="text-sm leading-6 text-neutral-200">{selected.title}</p>

                <div className="grid grid-cols-3 gap-3">
                  {[
                    { k: "风险评分", v: selected.score },
                    { k: "源 IP", v: selected.srcIp ?? "—" },
                    { k: "目的 IP", v: selected.dstIp ?? "—" },
                  ].map((x) => (
                    <div key={x.k} className="panel-2 p-3">
                      <div className="micro-label">{x.k}</div>
                      <div className="num mt-1.5 truncate text-sm text-neutral-100">{x.v}</div>
                    </div>
                  ))}
                </div>

                <section>
                  <div className="micro-label mb-2">EVIDENCE · 量化证据</div>
                  <div className="space-y-1.5 rounded-md border p-3" style={{ borderColor: "var(--line)", background: "var(--surface-2)" }}>
                    {Object.entries(selected.evidence as Record<string, unknown>).map(([k, v]) => (
                      <div key={k} className="flex items-start justify-between gap-4 py-1 text-xs">
                        <span className="shrink-0 pt-0.5 text-neutral-500">{k}</span>
                        <div className="max-w-[70%] text-right"><EvidenceValue v={v} /></div>
                      </div>
                    ))}
                  </div>
                </section>

                <section>
                  <div className="micro-label mb-2">RELATED SESSIONS · 关联会话（{(selected.relatedSessions as string[]).length}）</div>
                  <div className="flex flex-wrap gap-1.5">
                    {(selected.relatedSessions as string[]).map((s) => (
                      <span key={s} className="num rounded bg-white/5 px-2 py-1 text-[10px] text-neutral-400">{s}</span>
                    ))}
                  </div>
                </section>

                <div className="flex gap-3 border-t pt-4" style={{ borderColor: "var(--line)" }}>
                  <button
                    onClick={() => { update.mutate({ id: selected.id, status: "confirmed" }); setSelected({ ...selected, status: "confirmed" }); }}
                    className="flex items-center gap-1.5 rounded-md px-4 py-2 text-xs font-medium text-black"
                    style={{ background: "var(--mint)" }}
                  >
                    <Check className="h-3.5 w-3.5" /> 确认告警
                  </button>
                  <button
                    onClick={() => { update.mutate({ id: selected.id, status: "dismissed" }); setSelected({ ...selected, status: "dismissed" }); }}
                    className="flex items-center gap-1.5 rounded-md border px-4 py-2 text-xs text-neutral-300"
                    style={{ borderColor: "var(--line)" }}
                  >
                    <X className="h-3.5 w-3.5" /> 忽略
                  </button>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
