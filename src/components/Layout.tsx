import { NavLink, Outlet } from "react-router";
import { LayoutDashboard, Database, Radar, GitBranch, ShieldAlert, Activity, UploadCloud } from "lucide-react";

const NAV = [
  { to: "/", label: "态势总览", en: "OVERVIEW", icon: LayoutDashboard },
  { to: "/fields", label: "元数据建模", en: "METADATA MODEL", icon: Database },
  { to: "/sessions", label: "会话检索", en: "SESSIONS", icon: Radar },
  { to: "/ingest", label: "数据接入", en: "PCAP INGEST", icon: UploadCloud },
  { to: "/analysis", label: "行为关联分析", en: "CORRELATION", icon: GitBranch },
  { to: "/alerts", label: "告警中心", en: "ALERTS", icon: ShieldAlert },
];

export default function Layout() {
  return (
    <div className="flex min-h-screen" style={{ background: "var(--bg)" }}>
      <aside className="fixed inset-y-0 left-0 z-30 flex w-60 flex-col border-r" style={{ background: "var(--surface)", borderColor: "var(--line)" }}>
        <div className="flex items-center gap-3 px-5 py-5 border-b" style={{ borderColor: "var(--line)" }}>
          <div className="flex h-9 w-9 items-center justify-center rounded-md" style={{ background: "var(--mint-dim)" }}>
            <Activity className="h-5 w-5" style={{ color: "var(--mint)" }} />
          </div>
          <div>
            <div className="font-display text-sm font-semibold leading-tight">元数据建模分析平台</div>
            <div className="micro-label mt-0.5">METADATA ANALYTICS</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-4">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === "/"}
              className={({ isActive }) =>
                `group flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors ${
                  isActive ? "font-medium" : "text-neutral-400 hover:text-neutral-100"
                }`
              }
              style={({ isActive }) =>
                isActive ? { background: "var(--mint-dim)", color: "var(--mint)" } : {}
              }
            >
              <n.icon className="h-4 w-4 shrink-0" />
              <span className="flex-1 whitespace-nowrap">{n.label}</span>
              <span className="micro-label hidden opacity-60 2xl:inline">{n.en}</span>
            </NavLink>
          ))}
        </nav>
        <div className="border-t px-5 py-4" style={{ borderColor: "var(--line)" }}>
          <div className="micro-label">SYSTEM STATUS</div>
          <div className="mt-2 flex items-center gap-2 text-xs text-neutral-400">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-60" style={{ background: "var(--mint)" }} />
              <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: "var(--mint)" }} />
            </span>
            采集探针在线 · 元数据入库中
          </div>
        </div>
      </aside>
      <main className="ml-60 flex-1 px-8 py-6">
        <Outlet />
      </main>
    </div>
  );
}

export function PageHeader({ title, en, desc, extra }: { title: string; en: string; desc?: string; extra?: React.ReactNode }) {
  return (
    <div className="mb-6 flex items-end justify-between">
      <div>
        <div className="micro-label">{en}</div>
        <h1 className="font-display mt-1 text-2xl font-semibold tracking-tight">{title}</h1>
        {desc && <p className="mt-1 text-sm text-neutral-400">{desc}</p>}
      </div>
      {extra}
    </div>
  );
}
