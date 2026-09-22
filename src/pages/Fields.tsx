import { useMemo, useState } from "react";
import { trpc } from "@/providers/trpc";
import { FIELD_TYPE_LABEL } from "@/lib/format";
import { Search } from "lucide-react";

export default function FieldCatalog() {
  const { data } = trpc.meta.fieldCatalog.useQuery();
  const [active, setActive] = useState<string>("all");
  const [kw, setKw] = useState("");

  const filtered = useMemo(() => {
    if (!data) return [];
    return data.categories
      .filter((c) => active === "all" || c.code === active)
      .map((c) => ({
        ...c,
        fields: c.fields.filter(
          (f) => !kw || f.label.includes(kw) || f.key.toLowerCase().includes(kw.toLowerCase()) || f.desc.includes(kw),
        ),
      }))
      .filter((c) => c.fields.length > 0);
  }, [data, active, kw]);

  if (!data) return <div className="py-20 text-center text-sm text-neutral-500">数据加载中…</div>;

  return (
    <div>
      <div className="mb-4 flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-neutral-500" />
          <input
            value={kw}
            onChange={(e) => setKw(e.target.value)}
            placeholder="搜索字段名 / key / 描述…"
            className="w-full rounded-md border bg-transparent py-2 pl-9 pr-3 text-sm outline-none placeholder:text-neutral-600 focus:border-neutral-500"
            style={{ borderColor: "var(--line)", background: "var(--surface)" }}
          />
        </div>
        <div className="flex flex-wrap gap-1.5">
          <button
            onClick={() => setActive("all")}
            className="rounded-md px-3 py-1.5 text-xs transition-colors"
            style={active === "all" ? { background: "var(--mint-dim)", color: "var(--mint)" } : { color: "#9ca3af", background: "var(--surface)" }}
          >
            全部（{data.total}）
          </button>
          {data.categories.map((c) => (
            <button
              key={c.code}
              onClick={() => setActive(c.code)}
              className="rounded-md px-3 py-1.5 text-xs transition-colors"
              style={active === c.code ? { background: "var(--mint-dim)", color: "var(--mint)" } : { color: "#9ca3af", background: "var(--surface)" }}
            >
              {c.label}（{c.count}）
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-5">
        {filtered.map((c) => (
          <section key={c.code} className="panel overflow-hidden">
            <header className="flex items-center justify-between border-b px-5 py-3.5" style={{ borderColor: "var(--line)", background: "var(--surface-2)" }}>
              <div className="flex items-center gap-3">
                <span className="font-display text-sm font-semibold">{c.label}</span>
                <span className="micro-label">{c.en}</span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-neutral-500">{c.desc}</span>
                <span className="num rounded px-2 py-0.5 text-xs" style={{ background: "var(--mint-dim)", color: "var(--mint)" }}>{c.fields.length} 字段</span>
              </div>
            </header>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-neutral-500">
                  <th className="px-5 py-2.5 font-medium w-44">字段 key</th>
                  <th className="px-3 py-2.5 font-medium w-36">中文名</th>
                  <th className="px-3 py-2.5 font-medium w-20">类型</th>
                  <th className="px-3 py-2.5 font-medium w-16">单位</th>
                  <th className="px-3 py-2.5 font-medium">建模说明</th>
                  <th className="px-5 py-2.5 font-medium w-44">示例</th>
                </tr>
              </thead>
              <tbody>
                {c.fields.map((f) => (
                  <tr key={f.key} className="border-t hover:bg-white/[0.03]" style={{ borderColor: "var(--line)" }}>
                    <td className="num px-5 py-2.5 text-xs" style={{ color: "var(--mint)" }}>{f.key}</td>
                    <td className="px-3 py-2.5 text-neutral-200">{f.label}</td>
                    <td className="px-3 py-2.5">
                      <span className="rounded bg-white/5 px-1.5 py-0.5 text-[11px] text-neutral-400">{FIELD_TYPE_LABEL[f.type]}</span>
                    </td>
                    <td className="px-3 py-2.5 text-xs text-neutral-500">{f.unit ?? "—"}</td>
                    <td className="px-3 py-2.5 text-xs leading-5 text-neutral-400">{f.desc}</td>
                    <td className="num px-5 py-2.5 text-xs text-neutral-500">{f.example ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        ))}
        {filtered.length === 0 && <div className="py-16 text-center text-sm text-neutral-500">没有匹配的字段</div>}
      </div>
    </div>
  );
}
