import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtBytes, fmtTime, SEVERITY_STYLE, CATEGORY_STYLE } from "@/lib/format";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell,
} from "recharts";
import { ArrowRight } from "lucide-react";
import { Link } from "react-router";

const MINT = "#00d9a3";
const SEV_COLORS: Record<string, string> = { critical: "#ff4444", high: "#ff8c42", medium: "#ffd166", low: "#6b7280" };
const CAT_COLORS: Record<string, string> = { attack: "#ff8c42", c2: "#ff4444", data: "#00d9a3", baseline: "#7aa2ff" };
const PROTO_COLORS = ["#00d9a3", "#7aa2ff", "#ffd166", "#ff8c42", "#ff4444", "#9d7aff", "#4dd0e1", "#6b7280"];

function Kpi({ label, en, value, sub, accent }: { label: string; en: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="panel p-5">
      <div className="micro-label">{en}</div>
      <div className="mt-3 flex items-baseline gap-2">
        <span className="num font-display text-3xl font-semibold" style={accent ? { color: accent } : {}}>{value}</span>
        <span className="text-sm text-neutral-400">{label}</span>
      </div>
      {sub && <div className="mt-2 text-xs text-neutral-500">{sub}</div>}
    </div>
  );
}

const tooltipStyle = {
  contentStyle: { background: "#1a1a1a", border: "1px solid #262626", borderRadius: 8, fontSize: 12 },
  labelStyle: { color: "#9ca3af" },
};

export default function Dashboard() {
  const { data } = trpc.dashboard.overview.useQuery(undefined, { refetchInterval: 30000 });

  if (!data) {
    return <div className="py-20 text-center text-sm text-neutral-500">数据加载中…</div>;
  }

  const trend = data.trend.map((t) => ({ ...t, day: t.day.slice(5), mb: Number((t.bytes / 1048576).toFixed(0)) }));

  return (
    <div>
      <PageHeader title="态势总览" en="SECURITY OVERVIEW" desc="基于全量会话元数据的建模分析态势，每 30 秒自动刷新" />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-6">
        <Kpi en="SESSIONS" label="会话" value={data.sessionCount.toLocaleString()} sub="近 7 天采集入库" />
        <Kpi en="HOSTS" label="活跃主机" value={data.hostCount} sub="产生会话的源主机" />
        <Kpi en="MODEL FIELDS" label="建模字段" value={data.fieldCount} sub="10 大类元数据字段" />
        <Kpi en="RULES" label="分析规则" value={data.ruleCount} sub="4 大类行为关联场景" />
        <Kpi en="ALERTS" label="告警" value={data.alertCount} accent="#ff8c42" sub="全量分析结果" />
        <Kpi en="OPEN" label="待处置" value={data.openAlerts} accent="#ff4444" sub="尚未确认的告警" />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="panel p-5 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <div className="micro-label">TRAFFIC TREND</div>
              <div className="mt-1 text-sm font-medium">近 7 天会话量与流量趋势</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={trend}>
              <defs>
                <linearGradient id="gCount" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={MINT} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={MINT} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="day" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} />
              <YAxis yAxisId="l" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} width={40} />
              <YAxis yAxisId="r" orientation="right" tick={{ fill: "#6b7280", fontSize: 11 }} axisLine={false} tickLine={false} width={48} unit="M" />
              <Tooltip {...tooltipStyle} />
              <Area yAxisId="l" type="monotone" dataKey="count" name="会话数" stroke={MINT} fill="url(#gCount)" strokeWidth={2} />
              <Area yAxisId="r" type="monotone" dataKey="mb" name="流量(MB)" stroke="#7aa2ff" fill="none" strokeWidth={1.5} strokeDasharray="4 3" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="panel p-5">
          <div className="micro-label">ALERT SEVERITY</div>
          <div className="mt-1 text-sm font-medium">告警严重级别分布</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie data={data.severityDist} dataKey="count" nameKey="name" innerRadius={55} outerRadius={80} paddingAngle={3}>
                {data.severityDist.map((s) => <Cell key={s.name} fill={SEV_COLORS[s.name] ?? "#6b7280"} />)}
              </Pie>
              <Tooltip {...tooltipStyle} formatter={(v: number, n: string) => [v, SEVERITY_STYLE[n]?.label ?? n]} />
            </PieChart>
          </ResponsiveContainer>
          <div className="mt-1 grid grid-cols-2 gap-2">
            {data.severityDist.map((s) => (
              <div key={s.name} className="flex items-center gap-2 text-xs text-neutral-400">
                <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLORS[s.name] }} />
                {SEVERITY_STYLE[s.name]?.label ?? s.name}
                <span className="num ml-auto text-neutral-200">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <div className="panel p-5">
          <div className="micro-label">CORRELATION CATEGORIES</div>
          <div className="mt-1 text-sm font-medium">行为关联分析命中分布</div>
          <ResponsiveContainer width="100%" height={210}>
            <BarChart data={data.categoryDist} layout="vertical" margin={{ left: 8 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="name" width={72} tick={{ fill: "#9ca3af", fontSize: 12 }}
                tickFormatter={(v: string) => CATEGORY_STYLE[v]?.label ?? v} axisLine={false} tickLine={false} />
              <Tooltip {...tooltipStyle} formatter={(v: number, n: string, p: { payload?: { name?: string } }) => [v, CATEGORY_STYLE[p?.payload?.name ?? ""]?.label ?? n]} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} barSize={18}>
                {data.categoryDist.map((c) => <Cell key={c.name} fill={CAT_COLORS[c.name] ?? MINT} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="panel p-5">
          <div className="micro-label">PROTOCOL MIX</div>
          <div className="mt-1 text-sm font-medium">应用协议分布</div>
          <div className="mt-4 space-y-2.5">
            {data.protocolDist.slice(0, 7).map((p, i) => {
              const max = data.protocolDist[0]?.count ?? 1;
              return (
                <div key={p.name}>
                  <div className="mb-1 flex justify-between text-xs">
                    <span className="text-neutral-300">{p.name}</span>
                    <span className="num text-neutral-500">{p.count}</span>
                  </div>
                  <div className="h-1.5 rounded-full" style={{ background: "#1f1f1f" }}>
                    <div className="h-1.5 rounded-full" style={{ width: `${(p.count / max) * 100}%`, background: PROTO_COLORS[i % PROTO_COLORS.length] }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="panel p-5">
          <div className="micro-label">TOP TALKERS</div>
          <div className="mt-1 text-sm font-medium">流量主机排行</div>
          <div className="mt-3 space-y-1">
            {data.topTalkers.map((t, i) => (
              <div key={t.srcIp} className="flex items-center gap-3 rounded-md px-2 py-1.5 text-xs hover:bg-white/5">
                <span className="num w-4 text-neutral-600">{i + 1}</span>
                <span className="num flex-1 text-neutral-200">{t.srcIp}</span>
                {t.maxThreat >= 80 && <span className="rounded px-1.5 py-0.5 text-[10px]" style={{ background: "rgba(255,68,68,0.12)", color: "#ff4444" }}>高风险</span>}
                <span className="num text-neutral-400">{t.sessions} 会话</span>
                <span className="num w-16 text-right" style={{ color: MINT }}>{fmtBytes(t.bytes)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="panel mt-4 p-5">
        <div className="mb-3 flex items-center justify-between">
          <div>
            <div className="micro-label">LATEST ALERTS</div>
            <div className="mt-1 text-sm font-medium">最新告警</div>
          </div>
          <Link to="/alerts" className="flex items-center gap-1 text-xs hover:underline" style={{ color: MINT }}>
            进入告警中心 <ArrowRight className="h-3 w-3" />
          </Link>
        </div>
        <div className="space-y-1">
          {data.latestAlerts.length === 0 && (
            <div className="py-6 text-center text-xs text-neutral-500">暂无告警 —— 请先到「行为关联分析」运行分析任务</div>
          )}
          {data.latestAlerts.map((a) => {
            const sev = SEVERITY_STYLE[a.severity];
            return (
              <div key={a.id} className="flex items-center gap-3 rounded-md px-2 py-2 text-sm hover:bg-white/5">
                <span className="rounded px-2 py-0.5 text-[11px] font-medium" style={{ background: sev?.bg, color: sev?.color }}>{sev?.label}</span>
                <span className="flex-1 truncate text-neutral-200">{a.title}</span>
                <span className="text-xs text-neutral-500">{CATEGORY_STYLE[a.category]?.label}</span>
                <span className="num text-xs text-neutral-500">{fmtTime(a.createdAt)}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
