import BulkDelete, { PageSelection, useRowSelection } from "@/components/BulkDelete";
import ListPagination from "@/components/ListPagination";
import { useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtBytes, fmtTime, fmtDuration } from "@/lib/format";
import { FIELD_CATEGORIES } from "@contracts/fields";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { toast } from "sonner";
import { Search } from "lucide-react";

const APP_PROTOCOLS = ["HTTPS", "HTTP", "DNS", "SSH", "SMB", "FTP", "SMTP", "RDP", "TELNET", "TOR", "WMI", "OTHER"];

export default function Sessions() {
  const [page, setPage] = useState(1);
  const [keyword, setKeyword] = useState("");
  const [kwInput, setKwInput] = useState("");
  const [appProtocol, setAppProtocol] = useState("");
  const [direction, setDirection] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const utils = trpc.useUtils();
  const selection = useRowSelection(`${keyword}:${appProtocol}:${direction}`);
  const { data } = trpc.session.list.useQuery({
    page, pageSize: 10, keyword: keyword || undefined,
    appProtocol: appProtocol || undefined, direction: direction || undefined,
  });
  function deleted(result) {
    toast.success(`已删除 ${result.deleted} 条会话`);
    selection.clear();
    setSelected(null);
    setPage(1);
    utils.session.list.invalidate();
    utils.dashboard.overview.invalidate();
    utils.session.bySessionId.invalidate();
    utils.session.protocols.invalidate();
    utils.ingest.batches.invalidate();
    utils.model.matchSessions.invalidate();
  }
  const deleteMany = trpc.session.deleteMany.useMutation({ onSuccess: deleted, onError: error => toast.error(error.message) });
  const deleteAll = trpc.session.deleteAll.useMutation({ onSuccess: deleted, onError: error => toast.error(error.message) });
  const deleting = deleteMany.isPending || deleteAll.isPending;
  const detail = trpc.session.bySessionId.useQuery(
    { sessionId: selected! },
    { enabled: !!selected },
  );


  const selBtn = (active: boolean) =>
    active
      ? { background: "var(--mint-dim)", color: "var(--mint)" }
      : { color: "#4b5563", background: "var(--surface)" };

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
            className="w-full rounded-md border py-2 pl-9 pr-3 text-sm outline-none placeholder:text-neutral-500 focus:border-neutral-500"
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

      <BulkDelete entity="会话" selectedCount={selection.ids.size} total={data?.total} pending={deleting}
        onSelected={() => deleteMany.mutateAsync({ ids: [...selection.ids] })}
        onAll={() => deleteAll.mutateAsync({ confirm: "DELETE_ALL" })} />

      <div className="panel overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
              <th className="w-12 px-4 py-3"><PageSelection ids={data?.rows.map(row => row.id) ?? []} selected={selection.ids} onChange={() => selection.togglePage(data?.rows.map(row => row.id) ?? [])} disabled={deleting} /></th>
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
                className="cursor-pointer border-t hover:bg-slate-50"
                style={{ borderColor: "var(--line)" }}
              >
                <td className="px-4 py-2.5" onClick={event => event.stopPropagation()}><input type="checkbox" aria-label={`选择会话 ${s.sessionId}`} checked={selection.ids.has(s.id)} disabled={deleting} onChange={() => selection.toggle(s.id)} className="h-4 w-4 accent-emerald-700" /></td>
                <td className="num px-4 py-2.5 text-xs" style={{ color: "var(--mint)" }}>{s.sessionId}</td>
                <td className="num px-3 py-2.5 text-xs text-neutral-800">{s.srcIp}:{s.srcPort}</td>
                <td className="num px-3 py-2.5 text-xs text-neutral-800">{s.dstIp}:{s.dstPort}</td>
                <td className="px-3 py-2.5">
                  <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] text-neutral-700">{s.appProtocol}</span>
                  <span className="ml-1 text-[11px] text-neutral-500">{s.protocol}</span>
                </td>
                <td className="px-3 py-2.5 text-xs text-neutral-600">{s.direction}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-700">{s.upPackets} / {s.downPackets}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-700 target">{fmtBytes(s.upBytes)} / {fmtBytes(s.downBytes)}</td>
                <td className="num px-3 py-2.5 text-right text-xs text-neutral-600">{fmtDuration(s.duration)}</td>
                <td className="num px-4 py-2.5 text-right text-xs text-neutral-500">{fmtTime(s.startTime)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {data && data.rows.length === 0 && <div className="py-16 text-center text-sm text-neutral-500">没有匹配的会话</div>}
      </div>

      <ListPagination label="会话" page={page} total={data?.total} onPageChange={setPage} />

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
                      <span className="text-xs font-semibold text-neutral-800">{cat.label}</span>
                      <span className="micro-label">{cat.en}</span>
                      <span className="num text-[10px] text-neutral-500">{entries.length} 项</span>
                    </div>
                    <div className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-md border p-3" style={{ borderColor: "var(--line)", background: "var(--surface-2)" }}>
                      {entries.map(({ f, v }) => (
                        <div key={f.key} className="flex items-baseline justify-between gap-2 py-1 text-xs">
                          <span className="shrink-0 text-neutral-500" title={f.desc}>{f.label}</span>
                          <span className="num truncate text-right text-neutral-800" title={String(v)}>
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
