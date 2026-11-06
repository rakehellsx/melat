import ListPagination, { usePageRows } from "@/components/ListPagination";
import { useRef, useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import FieldCatalog from "./Fields";
import {
  DIMENSIONS, METRIC_FIELDS, AGG_LABEL, OP_LABEL, MODELING_STEPS,
  type MetricDef, type FilterDef, type HavingDef, type AggFn, type FilterOp,
} from "@contracts/modeling";
import { SEVERITY_STYLE, fmtBytes, fmtTime, fmtDuration } from "@/lib/format";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Plus, Trash2, Play, Save, ShieldPlus, Database, Boxes, ChevronRight } from "lucide-react";
import { toast } from "sonner";

type Severity = "critical" | "high" | "medium" | "low";

interface RunResult {
  columns: string[];
  rows: Record<string, unknown>[];
  matched: number;
  durationMs: number;
}

const inputCls =
  "rounded-md border bg-transparent px-3 py-2 text-sm outline-none placeholder:text-neutral-500 focus:border-neutral-500";
const inputStyle = { borderColor: "var(--line)", background: "var(--surface-2)" } as const;

function fmtCell(v: unknown): string {
  if (v === null || v === undefined) return "-";
  if (typeof v === "number" && v > 10000) return fmtBytes(v);
  return String(v);
}

export default function Modeling() {
  const utils = trpc.useUtils();
  const [tab, setTab] = useState<"builder" | "catalog">("builder");

  // ---- 模型定义状态 ----
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [dimensions, setDimensions] = useState<string[]>([]);
  const [fieldSearch, setFieldSearch] = useState("");
  const [fieldCategory, setFieldCategory] = useState("");
  const availableFields = DIMENSIONS.filter(f => (!fieldCategory || f.category === fieldCategory) &&
    (!fieldSearch || `${f.key} ${f.label}`.toLowerCase().includes(fieldSearch.toLowerCase())));
  const fieldPage = usePageRows(availableFields, `${fieldSearch}:${fieldCategory}`);
  const [metrics, setMetrics] = useState<MetricDef[]>([]);
  const [filters, setFilters] = useState<FilterDef[]>([]);
  const [having, setHaving] = useState<HavingDef | null>(null);
  const [result, setResult] = useState<RunResult | null>(null);
  const [detailId, setDetailId] = useState<number | null>(null);

  const [modelPage, setModelPage] = useState(1);
  const [resultPage, setResultPage] = useState(1);
  const lastRun = useRef<{ id?: number; definition?: unknown }>({});
  const models = trpc.model.list.useQuery({ page: modelPage });
  const runMut = trpc.model.run.useMutation({
    onSuccess: (r) => { setResult(r); toast.success(`模型运行完成：${r.matched} 个分组命中（${r.durationMs}ms）`); },
    onError: (e) => toast.error(e.message),
  });
  const createMut = trpc.model.create.useMutation({
    onSuccess: () => {
      toast.success("模型已保存");
      setModelPage(1);
      utils.model.list.invalidate();
    },
    onError: (e) => toast.error(`保存失败：${e.message}`),
  });
  const runSavedMut = trpc.model.runSaved.useMutation({
    onSuccess: (r) => { setResult(r); setTab("builder"); toast.success(`运行完成：${r.matched} 个分组命中`); },
    onError: (e) => toast.error(e.message),
  });
  const delMut = trpc.model.delete.useMutation({
    onSuccess: () => { toast.success("模型已删除"); utils.model.list.invalidate(); },
  });
  const alertMut = trpc.model.createAlerts.useMutation({
    onSuccess: (r) => {
      toast.success(`已生成 ${r.alerts} 条告警，请前往告警中心查看`);
      utils.dashboard.overview.invalidate();
    },
    onError: (e) => toast.error(e.message),
  });

  function runDefinition() {
    lastRun.current = { definition: def };
    setResultPage(1);
    runMut.mutate({ ...def, page: 1 });
  }
  function runSaved(id: number) {
    lastRun.current = { id };
    setResultPage(1);
    runSavedMut.mutate({ id, page: 1 });
  }
  function changeResultPage(page: number) {
    setResultPage(page);
    if (lastRun.current.id) runSavedMut.mutate({ id: lastRun.current.id, page });
    else runMut.mutate({ ...(lastRun.current.definition as object), page });
  }

  const def = { name, description, severity, dimensions, metrics, filters, having };
  const valid = name.trim() && dimensions.length > 0 && metrics.length > 0;

  function toggleDim(key: string) {
    setDimensions((ds) => (ds.includes(key) ? ds.filter((d) => d !== key) : [...ds, key]));
  }
  function addMetric() {
    const f = METRIC_FIELDS[0];
    setMetrics((ms) => [...ms, { field: f.key, agg: f.aggs[0], alias: `${f.label}` }]);
  }
  function addFilter() {
    setFilters((fs) => [...fs, { field: "appProtocol", op: "eq", value: "" }]);
  }

  const stepDone = [
    name.trim().length > 0,
    dimensions.length > 0,
    metrics.length > 0,
    true,
    !!result,
  ];

  return (
    <div>
      <PageHeader
        title="数据建模"
        en="METADATA MODELING"
        desc={`可用 ${DIMENSIONS.length} 个字段进行分组、过滤与度量，通过五个步骤完成行为建模`}
      />

      <div className="mb-5 flex gap-1.5">
        {([
          { key: "builder", label: "模型构建", icon: Boxes },
          { key: "catalog", label: "字段库（176 字段）", icon: Database },
        ] as const).map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className="flex items-center gap-2 rounded-md px-4 py-2 text-sm transition-colors"
            style={tab === t.key ? { background: "var(--mint-dim)", color: "var(--mint)" } : { color: "#4b5563", background: "var(--surface)" }}
          >
            <t.icon className="h-4 w-4" /> {t.label}
          </button>
        ))}
      </div>

      {tab === "catalog" && <FieldCatalog />}

      {tab === "builder" && (
        <div className="space-y-5">
          {/* 步骤条 */}
          <div className="panel flex items-center gap-0 overflow-x-auto px-2 py-3">
            {MODELING_STEPS.map((s, i) => (
              <div key={s.no} className="flex flex-1 items-center min-w-[150px]">
                <div className="flex items-center gap-2.5 px-3">
                  <span
                    className="num flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-xs font-semibold"
                    style={stepDone[i]
                      ? { background: "var(--mint)", color: "#fff" }
                      : { background: "var(--surface-2)", color: "#6b7280", border: "1px solid var(--line)" }}
                  >
                    {s.no}
                  </span>
                  <div>
                    <div className="whitespace-nowrap text-xs font-medium text-neutral-800">{s.title}</div>
                    <div className="whitespace-nowrap text-[10px] text-neutral-500">{s.desc}</div>
                  </div>
                </div>
                {i < MODELING_STEPS.length - 1 && <div className="h-px flex-1" style={{ background: "var(--line)" }} />}
              </div>
            ))}
          </div>

          {/* 已构建模型列表 */}
          <div className="panel overflow-hidden">
            <div className="flex items-center justify-between px-5 pt-4 pb-3">
              <span className="micro-label">SAVED MODELS · 已构建模型（{models.data?.total ?? 0}）</span>
              <span className="text-[10px] text-neutral-500">点击模型查看命中的会话明细</span>
            </div>
            {models.data && models.data.rows.length > 0 ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
                    <th className="px-5 py-2.5 font-medium">模型</th>
                    <th className="px-4 py-2.5 font-medium">告警级别</th>
                    <th className="px-4 py-2.5 font-medium">维度</th>
                    <th className="px-4 py-2.5 font-medium">度量</th>
                    <th className="px-4 py-2.5 font-medium">阈值</th>
                    <th className="px-4 py-2.5 font-medium">创建时间</th>
                    <th className="px-4 py-2.5 font-medium text-right">操作</th>
                    <th className="w-8" />
                  </tr>
                </thead>
                <tbody>
                  {models.data.rows.map((m) => {
                    const sev = SEVERITY_STYLE[m.severity];
                    const dims = (m.dimensions as string[]).map((d) => DIMENSIONS.find((x) => x.key === d)?.label ?? d);
                    const mets = (m.metrics as MetricDef[]).map((x) => x.alias);
                    const hv = m.having as HavingDef | null;
                    return (
                      <tr key={m.id} onClick={() => setDetailId(m.id)}
                        className="cursor-pointer border-t transition-colors hover:bg-slate-50"
                        style={{ borderColor: "var(--line)" }}>
                        <td className="px-5 py-3">
                          <div className="font-medium text-neutral-900">{m.name}</div>
                          <div className="mt-0.5 max-w-[280px] truncate text-xs text-neutral-500">{m.description || "—"}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: sev?.bg, color: sev?.color }}>{sev?.label}</span>
                        </td>
                        <td className="px-4 py-3 text-xs text-neutral-600">
                          <div className="max-w-[180px] truncate">{dims.join("、")}</div>
                        </td>
                        <td className="px-4 py-3 text-xs text-neutral-600">
                          <div className="max-w-[180px] truncate">{mets.join("、")}</div>
                        </td>
                        <td className="num px-4 py-3 text-xs text-neutral-600">
                          {hv ? `${mets[hv.metricIndex] ?? ""} ${OP_LABEL[hv.op]} ${hv.value}` : "—"}
                        </td>
                        <td className="num px-4 py-3 text-xs text-neutral-500">{fmtTime(m.createdAt)}</td>
                        <td className="px-4 py-3" onClick={(e) => e.stopPropagation()}>
                          <div className="flex justify-end gap-2">
                            <button onClick={() => runSaved(m.id)} title="运行模型"
                              className="flex items-center gap-1 rounded border px-2 py-1 text-[11px]" style={{ borderColor: "var(--mint)", color: "var(--mint)" }}>
                              <Play className="h-3 w-3" /> 运行
                            </button>
                            <button onClick={() => alertMut.mutate({ id: m.id })} title="将命中分组写入告警中心"
                              className="flex items-center gap-1 rounded border px-2 py-1 text-[11px] text-neutral-700" style={{ borderColor: "var(--line)" }}>
                              <ShieldPlus className="h-3 w-3" /> 告警
                            </button>
                            <button onClick={() => delMut.mutate({ id: m.id })} title="删除模型"
                              className="rounded p-1 text-neutral-500 hover:text-red-400">
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </td>
                        <td className="pr-4"><ChevronRight className="h-4 w-4 text-neutral-500" /></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="px-5 pb-5 text-xs text-neutral-500">暂无已构建模型 —— 按下方五个步骤完成建模并保存后，将在此列表中展示</div>
            )}
            <div className="px-5 pb-4"><ListPagination label="已构建模型" page={modelPage} total={models.data?.total} onPageChange={setModelPage} loading={models.isFetching} /></div>
          </div>

          {/* 步骤 1：定义模型 */}
          <section className="panel p-5">
            <StepTitle no={1} title="定义模型" />
            <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="模型名称，如：单源多端口扫描识别" className={inputCls} style={inputStyle} />
              <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="模型用途描述（可选）" className={inputCls} style={inputStyle} />
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-neutral-500 shrink-0">告警级别</span>
                {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
                  <button key={s} onClick={() => setSeverity(s)} className="rounded px-2.5 py-1.5 text-xs"
                    style={severity === s ? { background: SEVERITY_STYLE[s].bg, color: SEVERITY_STYLE[s].color } : { color: "#6b7280", background: "var(--surface-2)" }}>
                    {SEVERITY_STYLE[s].label}
                  </button>
                ))}
              </div>
            </div>
          </section>

          {/* 步骤 2：选择维度 */}
          <section className="panel p-5">
            <StepTitle no={2} title="选择维度" desc={`支持全部 ${DIMENSIONS.length} 个字段；已选择 ${dimensions.length} 个`} />
            <div className="mt-3 flex flex-wrap gap-3">
              <input aria-label="搜索建模字段" placeholder="搜索字段名称或 key" value={fieldSearch} onChange={e => setFieldSearch(e.target.value)} className={inputCls} style={inputStyle} />
              <select aria-label="建模字段分类" value={fieldCategory} onChange={e => setFieldCategory(e.target.value)} className={inputCls} style={inputStyle}>
                <option value="">全部分类（{DIMENSIONS.length} 字段）</option>
                {[...new Set(DIMENSIONS.map(f => f.category))].map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {fieldPage.rows.map((d) => (
                <button key={d.key} onClick={() => toggleDim(d.key)}
                  className="rounded-md px-3 py-1.5 text-xs transition-colors"
                  style={dimensions.includes(d.key)
                    ? { background: "var(--mint-dim)", color: "var(--mint)", border: "1px solid var(--mint)" }
                    : { color: "#4b5563", background: "var(--surface-2)", border: "1px solid var(--line)" }}>
                  {d.label}
                  <span className="num ml-1.5 opacity-50">{d.key}</span>
                </button>
              ))}
            </div>
            {fieldPage.total === 0 && <p className="mt-3 text-sm text-neutral-500">没有匹配的建模字段</p>}
            <ListPagination label="建模字段" page={fieldPage.page} total={fieldPage.total} onPageChange={fieldPage.setPage} />
            {dimensions.length > 0 && <div className="mt-3 flex flex-wrap gap-2" aria-label="已选建模字段">{dimensions.map(key => <button key={key} onClick={() => toggleDim(key)} className="rounded border px-2 py-1 text-xs" style={{ borderColor: "var(--mint)", color: "var(--mint)" }}>{DIMENSIONS.find(f => f.key === key)?.label} ×</button>)}</div>}
          </section>

          {/* 步骤 3：配置度量 */}
          <section className="panel p-5">
            <StepTitle no={3} title="配置度量" desc="聚合计算指标，可添加多个" />
            <div className="mt-3 space-y-2">
              {metrics.map((m, i) => {
                const fieldDef = METRIC_FIELDS.find((f) => f.key === m.field)!;
                return (
                  <div key={i} className="flex flex-wrap items-center gap-2">
                    <select value={m.field} onChange={(e) => {
                      const f = METRIC_FIELDS.find((x) => x.key === e.target.value)!;
                      setMetrics(metrics.map((x, j) => j === i ? { field: f.key, agg: f.aggs[0], alias: f.label } : x));
                    }} className={inputCls} style={inputStyle}>
                      {METRIC_FIELDS.map((f) => <option key={f.key} value={f.key}>{f.label}</option>)}
                    </select>
                    <select value={m.agg} onChange={(e) => setMetrics(metrics.map((x, j) => j === i ? { ...x, agg: e.target.value as AggFn } : x))} className={inputCls} style={inputStyle}>
                      {fieldDef.aggs.map((a) => <option key={a} value={a}>{AGG_LABEL[a]}</option>)}
                    </select>
                    <input value={m.alias} onChange={(e) => setMetrics(metrics.map((x, j) => j === i ? { ...x, alias: e.target.value } : x))}
                      placeholder="列别名" className={inputCls + " w-40"} style={inputStyle} />
                    <button onClick={() => setMetrics(metrics.filter((_, j) => j !== i))} className="rounded p-1.5 text-neutral-500 hover:text-red-400">
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                );
              })}
              <button onClick={addMetric} className="flex items-center gap-1.5 rounded-md border border-dashed px-3 py-1.5 text-xs text-neutral-600" style={{ borderColor: "var(--line)" }}>
                <Plus className="h-3.5 w-3.5" /> 添加度量
              </button>
            </div>
          </section>

          {/* 步骤 4：过滤与阈值 */}
          <section className="panel p-5">
            <StepTitle no={4} title="过滤与阈值" desc="过滤条件（WHERE）与告警触发阈值（HAVING，可选）" />
            <div className="mt-3 space-y-2">
              {filters.map((f, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <select value={f.field} onChange={(e) => setFilters(filters.map((x, j) => j === i ? { ...x, field: e.target.value } : x))} className={inputCls} style={inputStyle}>
                    <optgroup label="维度字段">
                      {DIMENSIONS.map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
                    </optgroup>
                    <optgroup label="数值字段">
                      {METRIC_FIELDS.filter((x) => x.key !== "*").map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
                    </optgroup>
                  </select>
                  <select value={f.op} onChange={(e) => setFilters(filters.map((x, j) => j === i ? { ...x, op: e.target.value as FilterOp } : x))} className={inputCls + " w-24"} style={inputStyle}>
                    {(Object.keys(OP_LABEL) as FilterOp[]).map((o) => <option key={o} value={o}>{OP_LABEL[o]}</option>)}
                  </select>
                  <input value={f.value} onChange={(e) => setFilters(filters.map((x, j) => j === i ? { ...x, value: e.target.value } : x))}
                    placeholder="值" className={inputCls + " w-44"} style={inputStyle} />
                  <button onClick={() => setFilters(filters.filter((_, j) => j !== i))} className="rounded p-1.5 text-neutral-500 hover:text-red-400">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              <div className="flex flex-wrap items-center gap-2">
                <button onClick={addFilter} className="flex items-center gap-1.5 rounded-md border border-dashed px-3 py-1.5 text-xs text-neutral-600" style={{ borderColor: "var(--line)" }}>
                  <Plus className="h-3.5 w-3.5" /> 添加过滤条件
                </button>
                <span className="mx-2 h-4 w-px" style={{ background: "var(--line)" }} />
                <label className="flex items-center gap-2 text-xs text-neutral-600">
                  <input type="checkbox" checked={!!having} onChange={(e) => setHaving(e.target.checked ? { metricIndex: 0, op: "gte", value: 0 } : null)} />
                  启用告警阈值
                </label>
                {having && (
                  <>
                    <select value={having.metricIndex} onChange={(e) => setHaving({ ...having, metricIndex: Number(e.target.value) })} className={inputCls} style={inputStyle}>
                      {metrics.map((m, i) => <option key={i} value={i}>{m.alias}</option>)}
                    </select>
                    <select value={having.op} onChange={(e) => setHaving({ ...having, op: e.target.value as FilterOp })} className={inputCls + " w-24"} style={inputStyle}>
                      {(["gt", "gte", "lt", "lte", "eq"] as FilterOp[]).map((o) => <option key={o} value={o}>{OP_LABEL[o]}</option>)}
                    </select>
                    <input type="number" value={having.value} onChange={(e) => setHaving({ ...having, value: Number(e.target.value) })} className={inputCls + " w-32"} style={inputStyle} />
                  </>
                )}
              </div>
            </div>
          </section>

          {/* 步骤 5：运行验证 */}
          <section className="panel p-5">
            <StepTitle no={5} title="运行验证" desc="对全量会话元数据执行模型，验证命中效果后保存" />
            <div className="mt-3 flex gap-3">
              <button
                onClick={() => valid && runDefinition()}
                disabled={!valid || runMut.isPending}
                className="flex items-center gap-2 rounded-md border px-4 py-2 text-sm disabled:opacity-40"
                style={{ borderColor: "var(--mint)", color: "var(--mint)" }}
              >
                <Play className="h-4 w-4" /> {runMut.isPending ? "运行中…" : "试运行"}
              </button>
              <button
                onClick={() => valid && createMut.mutate(def)}
                disabled={!valid || createMut.isPending}
                className="flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium text-white disabled:opacity-40"
                style={{ background: "var(--mint)" }}
              >
                <Save className="h-4 w-4" /> 保存模型
              </button>
              {!valid && <span className="self-center text-xs text-neutral-500">需完成：模型名称 + 至少 1 个维度 + 至少 1 个度量</span>}
            </div>

            {result && (
              <div className="mt-4">
                <div className="mb-2 flex items-center gap-3 text-xs text-neutral-500">
                  <span className="micro-label">RESULT</span>
                  <span>命中 <span className="num" style={{ color: "var(--mint)" }}>{result.matched}</span> 个分组 · {result.durationMs}ms</span>
                </div>
                <div className="overflow-x-auto rounded-md border" style={{ borderColor: "var(--line)" }}>
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
                        {result.columns.map((c) => <th key={c} className="px-4 py-2.5 font-medium">{c}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {result.rows.map((row, i) => {
                        const dimCount = Object.keys(row).filter((k) => k.startsWith("d")).length;
                        return (
                          <tr key={i} className="border-t hover:bg-slate-50" style={{ borderColor: "var(--line)" }}>
                            {result.columns.map((_, j) => (
                              <td key={j} className="num px-4 py-2 text-xs text-neutral-800">{fmtCell(j < dimCount ? row[`d${j}`] : row[`m${j - dimCount}`])}</td>
                            ))}
                          </tr>
                        );
                      })}
                      {result.rows.length === 0 && (
                        <tr><td colSpan={result.columns.length} className="py-8 text-center text-xs text-neutral-500">无命中分组 —— 可调整维度、过滤或阈值</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
                <ListPagination label="运行结果" page={resultPage} total={result.matched} onPageChange={changeResultPage} loading={runMut.isPending || runSavedMut.isPending} />
              </div>
            )}
          </section>
        </div>
      )}

      {/* 模型详情抽屉：命中分组 + 命中会话 */}
      <ModelDetailDrawer
        key={detailId ?? "closed"}
        model={models.data?.rows.find((m) => m.id === detailId) ?? null}
        onClose={() => setDetailId(null)}
        onCreateAlerts={(id) => alertMut.mutate({ id })}
      />
    </div>
  );
}

/** 模型详情：定义摘要、命中分组、命中会话明细 */
function ModelDetailDrawer({
  model, onClose, onCreateAlerts,
}: {
  model: {
    id: number; name: string; description: string; severity: string;
    dimensions: unknown; metrics: unknown; filters: unknown; having: unknown;
  } | null;
  onClose: () => void;
  onCreateAlerts: (id: number) => void;
}) {
  const [page, setPage] = useState(1);
  const [groupsPage, setGroupsPage] = useState(1);
  const q = trpc.model.matchSessions.useQuery(
    { id: model?.id ?? 0, page, groupsPage },
    { enabled: !!model },
  );
  if (!model) return null;

  const sev = SEVERITY_STYLE[model.severity];
  const dims = (model.dimensions as string[]).map((d) => DIMENSIONS.find((x) => x.key === d)?.label ?? d);
  const mets = (model.metrics as MetricDef[]).map((m) => {
    const f = METRIC_FIELDS.find((x) => x.key === m.field);
    return `${m.alias}（${AGG_LABEL[m.agg]}·${f?.label ?? m.field}）`;
  });
  const filters = model.filters as FilterDef[];
  const hv = model.having as HavingDef | null;
  const run = q.data?.run;
  const hitSessions = q.data?.sessions ?? [];

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent side="right" className="w-[860px] overflow-y-auto border-l sm:max-w-[860px]"
        style={{ background: "var(--surface)", borderColor: "var(--line)" }}>
        <SheetHeader>
          <SheetTitle className="flex items-center gap-3">
            <span>{model.name}</span>
            <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: sev?.bg, color: sev?.color }}>{sev?.label}</span>
          </SheetTitle>
        </SheetHeader>

        <div className="mt-4 space-y-5">
          {/* 模型定义 */}
          <section>
            <div className="micro-label mb-2">MODEL DEFINITION · 模型定义</div>
            <div className="panel-2 space-y-1.5 p-4 text-xs">
              {model.description && <div className="text-neutral-600">{model.description}</div>}
              <div><span className="text-neutral-500">分组维度：</span><span className="text-neutral-800">{dims.join("、")}</span></div>
              <div><span className="text-neutral-500">聚合度量：</span><span className="text-neutral-800">{mets.join("；")}</span></div>
              <div>
                <span className="text-neutral-500">过滤条件：</span>
                <span className="text-neutral-800">
                  {filters.length
                    ? filters.map((f) => `${DIMENSIONS.find((d) => d.key === f.field)?.label ?? METRIC_FIELDS.find((x) => x.key === f.field)?.label ?? f.field} ${OP_LABEL[f.op]} ${f.value}`).join(" 且 ")
                    : "无"}
                </span>
              </div>
              <div>
                <span className="text-neutral-500">告警阈值：</span>
                <span className="text-neutral-800">
                  {hv ? `${(model.metrics as MetricDef[])[hv.metricIndex]?.alias} ${OP_LABEL[hv.op]} ${hv.value}` : "未启用"}
                </span>
              </div>
            </div>
          </section>

          {/* 命中分组 */}
          <section>
            <div className="micro-label mb-2">
              HIT GROUPS · 命中分组（{q.isLoading ? "…" : run?.matched ?? 0}）
            </div>
            {run && run.rows.length > 0 ? (
              <div className="overflow-x-auto rounded-md border" style={{ borderColor: "var(--line)" }}>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
                      {run.columns.map((c) => <th key={c} className="px-3 py-2 font-medium">{c}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {run.rows.map((row, i) => {
                      const dimCount = Object.keys(row).filter((k) => k.startsWith("d")).length;
                      return (
                        <tr key={i} className="border-t" style={{ borderColor: "var(--line)" }}>
                          {run.columns.map((_, j) => (
                            <td key={j} className="num px-3 py-1.5 text-xs text-neutral-800">
                              {fmtCell(j < dimCount ? row[`d${j}`] : row[`m${j - dimCount}`])}
                            </td>
                          ))}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="panel-2 p-4 text-xs text-neutral-500">{q.isLoading ? "模型运行中…" : "当前数据下无命中分组"}</div>
            )}
            <ListPagination label="命中分组" page={groupsPage} total={run?.total} onPageChange={setGroupsPage} loading={q.isFetching} />
          </section>

          {/* 命中会话 */}
          <section>
            <div className="mb-2 flex items-center justify-between">
              <span className="micro-label">
                MATCHED SESSIONS · 命中会话（{q.isLoading ? "…" : q.data?.sessionTotal ?? 0} 条）
              </span>
              <button onClick={() => onCreateAlerts(model.id)}
                className="flex items-center gap-1.5 rounded border px-2.5 py-1 text-[11px] text-neutral-700" style={{ borderColor: "var(--line)" }}>
                <ShieldPlus className="h-3 w-3" /> 将命中写入告警中心
              </button>
            </div>
            <div className="overflow-x-auto rounded-md border" style={{ borderColor: "var(--line)" }}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs text-neutral-500" style={{ background: "var(--surface-2)" }}>
                    <th className="px-3 py-2 font-medium">会话 ID</th>
                    <th className="px-3 py-2 font-medium">源</th>
                    <th className="px-3 py-2 font-medium">目的</th>
                    <th className="px-3 py-2 font-medium">协议</th>
                    <th className="px-3 py-2 font-medium text-right">总字节</th>
                    <th className="px-3 py-2 font-medium text-right">包数</th>
                    <th className="px-3 py-2 font-medium text-right">时长</th>
                    <th className="px-3 py-2 font-medium">开始时间</th>
                    <th className="px-3 py-2 font-medium text-right">威胁分</th>
                  </tr>
                </thead>
                <tbody>
                  {hitSessions.map((s) => (
                    <tr key={s.id} className="border-t hover:bg-slate-50" style={{ borderColor: "var(--line)" }}>
                      <td className="num px-3 py-1.5 text-xs" style={{ color: "var(--mint)" }}>{s.sessionId}</td>
                      <td className="num px-3 py-1.5 text-xs text-neutral-800">{s.srcIp}:{s.srcPort}</td>
                      <td className="num px-3 py-1.5 text-xs text-neutral-800">{s.dstIp}:{s.dstPort}</td>
                      <td className="px-3 py-1.5 text-xs text-neutral-700">{s.appProtocol || s.protocol}</td>
                      <td className="num px-3 py-1.5 text-right text-xs text-neutral-800">{fmtBytes(s.upBytes + s.downBytes)}</td>
                      <td className="num px-3 py-1.5 text-right text-xs text-neutral-600">{s.upPackets + s.downPackets}</td>
                      <td className="num px-3 py-1.5 text-right text-xs text-neutral-600">{fmtDuration(s.duration)}</td>
                      <td className="num px-3 py-1.5 text-xs text-neutral-500">{fmtTime(s.startTime)}</td>
                      <td className="num px-3 py-1.5 text-right text-xs" style={{ color: s.threatScore >= 70 ? "#dc2626" : s.threatScore >= 40 ? "#c2410c" : "#6b7280" }}>{s.threatScore}</td>
                    </tr>
                  ))}
                  {hitSessions.length === 0 && (
                    <tr><td colSpan={9} className="py-8 text-center text-xs text-neutral-500">{q.isLoading ? "查询中…" : "无命中会话"}</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            <ListPagination label="命中会话" page={page} total={q.data?.sessionTotal} onPageChange={setPage} loading={q.isFetching} />
          </section>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function StepTitle({ no, title, desc }: { no: number; title: string; desc?: string }) {
  return (
    <div className="flex items-baseline gap-2.5">
      <span className="num flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-semibold" style={{ background: "var(--mint-dim)", color: "var(--mint)" }}>{no}</span>
      <span className="text-sm font-medium">{title}</span>
      {desc && <span className="text-xs text-neutral-500">{desc}</span>}
    </div>
  );
}
