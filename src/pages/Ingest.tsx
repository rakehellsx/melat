import { useRef, useState } from "react";
import { trpc } from "@/providers/trpc";
import { PageHeader } from "@/components/Layout";
import { fmtBytes, fmtTime } from "@/lib/format";
import { UploadCloud, FileBox, Trash2, Zap, ArrowRight } from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";

interface UploadResult {
  ok: boolean;
  batchId: number;
  filename: string;
  sizeBytes: number;
  packets: number;
  skipped: number;
  flows: number;
  imported: number;
  protoDist: Record<string, number>;
  durationMs: number;
}

export default function Ingest() {
  const utils = trpc.useUtils();
  const batches = trpc.ingest.batches.useQuery();
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<UploadResult | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const del = trpc.ingest.deleteBatch.useMutation({
    onSuccess: () => {
      toast.success("批次及其会话已删除");
      utils.ingest.batches.invalidate();
      utils.dashboard.overview.invalidate();
    },
  });
  const runAll = trpc.analysis.runAll.useMutation({
    onSuccess: (rs) => {
      const total = rs.reduce((s, r) => s + r.alerts, 0);
      toast.success(`全量分析完成：产出 ${total} 条告警`);
      utils.analysis.rules.invalidate();
      utils.dashboard.overview.invalidate();
    },
  });

  async function upload(file: File) {
    if (!file.name.toLowerCase().endsWith(".pcap") && !file.name.toLowerCase().endsWith(".cap")) {
      toast.error("请上传 .pcap 文件（classic pcap 格式）");
      return;
    }
    if (file.size > 50 * 1024 * 1024) {
      toast.error("文件超过 50MB 限制");
      return;
    }
    setUploading(true);
    setResult(null);
    try {
      const resp = await fetch("/api/upload/pcap", {
        method: "POST",
        headers: { "x-filename": encodeURIComponent(file.name), "Content-Type": "application/octet-stream" },
        body: file,
      });
      const data = await resp.json();
      if (!resp.ok) {
        toast.error(data.error ?? "解析失败");
      } else {
        setResult(data);
        toast.success(`解析完成：${data.packets} 个报文 → ${data.imported} 条会话入库`);
        utils.ingest.batches.invalidate();
        utils.dashboard.overview.invalidate();
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "上传失败");
    } finally {
      setUploading(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="数据接入"
        en="PCAP INGEST"
        desc="上传 pcap 抓包文件，解析为五元组会话元数据入库，可直接进入行为关联分析"
      />

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const f = e.dataTransfer.files?.[0];
          if (f) upload(f);
        }}
        onClick={() => inputRef.current?.click()}
        className="panel flex cursor-pointer flex-col items-center justify-center gap-3 border-dashed py-14 transition-colors"
        style={dragOver ? { borderColor: "var(--mint)", background: "var(--mint-dim)" } : {}}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.cap"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) upload(f);
            e.target.value = "";
          }}
        />
        <UploadCloud className="h-10 w-10" style={{ color: "var(--mint)" }} />
        <div className="text-sm text-neutral-200">
          {uploading ? "解析入库中…" : "拖拽 pcap 文件到此处，或点击选择文件"}
        </div>
        <div className="text-xs text-neutral-500">
          支持 classic pcap（Ethernet / IPv4 / TCP / UDP），自动解析 DNS、TLS SNI、HTTP 要素 · 单文件 ≤ 50MB
        </div>
      </div>

      {result && (
        <div className="panel mt-4 p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileBox className="h-5 w-5" style={{ color: "var(--mint)" }} />
              <div>
                <div className="text-sm font-medium">{decodeURIComponent(result.filename)}</div>
                <div className="micro-label mt-0.5">PARSE RESULT · BATCH #{result.batchId}</div>
              </div>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => runAll.mutate()}
                disabled={runAll.isPending}
                className="flex items-center gap-1.5 rounded-md px-3.5 py-2 text-xs font-medium text-black disabled:opacity-50"
                style={{ background: "var(--mint)" }}
              >
                <Zap className="h-3.5 w-3.5" /> {runAll.isPending ? "分析中…" : "运行全量分析"}
              </button>
              <Link
                to="/sessions"
                className="flex items-center gap-1.5 rounded-md border px-3.5 py-2 text-xs text-neutral-300"
                style={{ borderColor: "var(--line)" }}
              >
                查看会话 <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
            {[
              { k: "文件大小", v: fmtBytes(result.sizeBytes) },
              { k: "报文数", v: result.packets.toLocaleString() },
              { k: "会话流", v: result.flows },
              { k: "入库会话", v: result.imported },
              { k: "跳过报文", v: result.skipped },
              { k: "解析耗时", v: `${result.durationMs}ms` },
            ].map((x) => (
              <div key={x.k} className="panel-2 p-3">
                <div className="micro-label">{x.k}</div>
                <div className="num mt-1.5 text-lg font-semibold">{x.v}</div>
              </div>
            ))}
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs text-neutral-400">
            <span className="micro-label">PROTOCOLS</span>
            {Object.entries(result.protoDist).map(([k, v]) => (
              <span key={k} className="rounded bg-white/5 px-2 py-0.5">
                {k} <span className="num" style={{ color: "var(--mint)" }}>{v}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="panel mt-4 p-5">
        <div className="micro-label">INGEST HISTORY</div>
        <div className="mt-1 mb-3 text-sm font-medium">接入批次记录</div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-neutral-500">
              <th className="py-2 pr-3 font-medium">批次</th>
              <th className="py-2 pr-3 font-medium">文件名</th>
              <th className="py-2 pr-3 font-medium text-right">大小</th>
              <th className="py-2 pr-3 font-medium text-right">报文</th>
              <th className="py-2 pr-3 font-medium text-right">会话流</th>
              <th className="py-2 pr-3 font-medium text-right">耗时</th>
              <th className="py-2 pr-3 font-medium text-right">接入时间</th>
              <th className="py-2 font-medium text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {batches.data?.map((b) => (
              <tr key={b.id} className="border-t text-xs" style={{ borderColor: "var(--line)" }}>
                <td className="num py-2.5 pr-3" style={{ color: "var(--mint)" }}>#{b.id}</td>
                <td className="py-2.5 pr-3 text-neutral-200">{decodeURIComponent(b.filename)}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-400">{fmtBytes(b.sizeBytes)}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-300">{b.packets.toLocaleString()}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-300">{b.flows}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-400">{b.durationMs}ms</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-500">{fmtTime(b.createdAt)}</td>
                <td className="py-2.5 text-right">
                  <button
                    onClick={() => del.mutate({ id: b.id })}
                    className="rounded-md p-1.5 text-neutral-500 transition-colors hover:text-red-400"
                    title="删除批次及其会话"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </td>
              </tr>
            ))}
            {batches.data?.length === 0 && (
              <tr><td colSpan={8} className="py-8 text-center text-xs text-neutral-500">尚未接入过 pcap 数据</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
