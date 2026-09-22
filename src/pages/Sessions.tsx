import { useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtBytes, fmtTime, fmtDuration } from "@/lib/format";
import { FIELD_CATEGORIES } from "@contracts/fields";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Search, ChevronLeft, ChevronRight } from "lucide-react";

const APP_PROTOCOLS = ["HTTPS", "HTTP", "DNS", "SSH", "SMB", "FTP", "SMTP", "RDP", "TELNET", "TOR", "WMI", "OTHER"];

export default function Sessions() {
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState("");
  const [kwInput, setKwInput] = useState("");
  const [appProtocol, setAppProtocol] = useState("");
  const [direction, setDirection] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const { data } = trpc.session.list.useQuery({
    page, pageSize: 20, keyword: keyword || undefined,
    appProtocol: appProtocol || undefined, direction: direction || undefined,
  });
  const detail = trpc.session.bySessionId.useQuery(
    { sessionId: selected! },
    { enabled: !!selected },
  );

  const totalPages = data ? Math.max(1, Math.ceil(data.total / 20)) : 1;

  const selBtn = (active: boolean) =>
    active
      ? { background: "var(--mint-dim)", color: "var(--mint)" }
      : { color: "#9ca3af", background: "var(--surface)" };

  return (
    <div>
      <PageHeader title="会话检索" en="SESSION EXPLORER" desc="检索全量会话元数据，点击任意会话查看完整建模字段画像" />

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-500" />
          <input
            value={kwInput}
            onChange={(e) => setKwInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") { setKeyword(kwInput); setPage(1); } }}
            placeholder="IP / 会话 ID / 域名，回车检索"
            className="w-full rounded-md border py-2 pl-9 pr-3 text-sm outline-none placeholder:text-neutral-600 focus:border-neutral-500"
            style={{ borderColor: "var(--line)", background: "var(--surface)" }}
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button onClick={() => { setAppProtocol(""); setPage(1); }} className="rounded-md px-2.5 py-1.5 text-xs" style={selBtn(!appProtocol)}>全部协议</button>
          {APP_PROTOCOLS.map((p) => (
            <button key={p} onClick={() => { setAppProtocol(p); setPage(1); }} className="num rounded-md px-2.5 py-1.5 text-xs" style={selBtn(appProtocol === p)}>{p}</button>
          ))}
        </div>
        <div className="flex gap-1.5">
          {["", "内到外", "外到内", "内到内"].map((d) => (
            <button key={d || "all"} onClick={() => { setDirection(d); setPage(1); }} className="rounded-md px-2.5 py-1.5 text-xs" style={selBtn(direction === d)}>
              {d || "全部方向"}
            </button>
          ))}
        </div>
      </div>

      <div className="panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
              <th className="px-4 py-3 font-medium">会话 ID</th>
              <th className="px-3 py-3 font-medium">源 IP:端口</th>
              <th className="px-3 py-3 font-medium">目的 IP:端口</th>
              <th className="px-3 py-3 font-medium">协议</th>
              <th className="px-3 py-3 font-medium">方向</th>
              <th className="px-3 py-3 font-medium text-right">上/下行包数</th>
              <th className="px-3 py-3 font-medium text-right">上/下行字节</th>
              <th className="px-3 py-3 font-medium text-right">时长</th>
              <th className="px-4 py-3 font-medium text-right">开始时间</th>
            </tr>
          </thead>
          <tbody>
            {data?.rows.map((s) => (
              <tr
                key={s.sessionId}
                onClick={() => setSelected(s.sessionId)}
                className="cursor-pointer border-t hover:bg-white/[0.04]"
                style={{ borderColor: "var(--line)" }}
              >
                <td className="num px-4 py-2.5 text-xs" style={{ color: "var(--mint)" }}>{s.sessionId}</td>
                <td className="num px-3 py-2.5 text-xs text-neutral-200">{s.srcIp}:{s.srcPort}</td>
                <td className="num px-3 py-2.5 text-xs text-neutral-200">{s.dstIp}:{s.dstPort}</td>
                <td className="px-3 py-2.5">
                  <span className="rounded bg-white/5 px-1.5 py-0.5 text-[11px] text-neutral-300">{s.appProtocol}</span>
                  <span className="ml-1 text-[11px] text-neutral-600">{s.protocol}</span>
                </td>
                <td className="px-3 py-2.5 text-xs text-neutral-400">{s.direction}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-300">{s.upPackets} / {s.downPackets}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-300 target">{fmtBytes(s.upBytes)} / {fmtBytes(s.downBytes)}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-400">{fmtDuration(s.duration)}</td>
                <td className="num px-4 py-2.5 text-right text-xs text-neutral-500">{fmtTime(s.startTime)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.rows.length === 0 && <div className="py-16 text-center text-sm text-neutral-500">没有匹配的会话</div>}
      </div>

      <div className="mt-4 flex items-center justify-between text-sm text-neutral-400">
        <span className="num text-xs">共 {data?.total ?? 0} 条会话 · 第 {page}/{totalPages} 页</span>
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
        <SheetContent side="right" className="w-[720px] overflow-y-auto border-l sm:max-w-[720px]" style={{ background: "var(--surface)", borderColor: "var(--line)" }}>
          <SheetHeader>
            <SheetTitle className="flex items-center gap-3">
              <span className="num text-base" style={{ color: "var(--mint)" }}>{selected}</span>
              <span className="micro-label">FULL METADATA PROFILE</span>
            </SheetTitle>
          </SheetHeader>
          {detail.data ? (
            <div className="mt-4 space-y-5 pb-10">
              {FIELD_CATEGORIES.map((cat) => {
                const meta = detail.data.meta as Record<string, unknown>;
                const entries = cat.fields
                  .map((f) => ({ f, v: meta[f.key] }))
                  .filter(({ v }) => v !== null && v !== undefined && v !== "");
                if (entries.length === 0) return null;
                return (
                  <section key={cat.code}>
                    <div className="mb-2 flex items-center gap-2">
                      <span className="text-xs font-semibold text-neutral-200">{cat.label}</span>
                      <span className="micro-label">{cat.en}</span>
                      <span className="num text-[10px] text-neutral-600">{entries.length} 项</span>
                    </div>
                    <div className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-md border p-3" style={{ borderColor: "var(--line)", background: "var(--surface-2)" }}>
                      {entries.map(({ f, v }) => (
                        <div key={f.key} className="flex items-baseline justify-between gap-2 py-1 text-xs">
                          <span className="shrink-0 text-neutral-500" title={f.desc}>{f.label}</span>
                          <span className="num truncate text-right text-neutral-200" title={String(v)}>
                            {typeof v === "boolean" ? (v ? "是" : "否") : String(v)}{typeof v !== "boolean" && f.unit ? ` ${f.unit}` : ""}
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                );
              })}
            </div>
          ) : (
            <div className="py-16 text-center text-sm text-neutral-500">加载中…</div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
