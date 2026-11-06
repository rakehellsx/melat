import ListPagination from "@/components/ListPagination";
import { useEffect, useRef, useState } from "react";
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
  normalizedTimestamps?: number;
}

export default function Ingest() {
  const utils = trpc.useUtils();
  const [page, setPage] = useState(1);
  const batches = trpc.ingest.batches.useQuery({ page });
  const [dragOver, setDragOver] = useState(false);
  const [jobId, setJobId] = useState<string | null>(() => localStorage.getItem("melat-import-job"));
  const [uploading, setUploading] = useState(() => !!localStorage.getItem("melat-import-job"));
  const [uploadProgress, setUploadProgress] = useState(0);
  const [jobProgress, setJobProgress] = useState<{ status: string; packets: number; imported: number }>({ status: "queued", packets: 0, imported: 0 });
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

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const response = await fetch(`/api/rpc/ingest.job?input=${encodeURIComponent(JSON.stringify({ id: jobId }))}`);
        const job = await response.json();
        if (cancelled) return;
        if (!response.ok) throw new Error(job.detail ?? "查询导入状态失败");
        setJobProgress(job);
        if (job.status === "success" || job.status === "failed") {
          localStorage.removeItem("melat-import-job");
          setJobId(null);
          setUploading(false);
          if (job.status === "failed") toast.error(job.error ?? "导入失败，请重新上传");
          else {
            setResult(job.result);
            setPage(1);
            toast.success(`导入完成：${job.result.packets} 个报文 → ${job.result.imported} 条会话`);
            utils.ingest.batches.invalidate();
            utils.dashboard.overview.invalidate();
            utils.session.list.invalidate();
          }
          return;
        }
      } catch (error) {
        if (!cancelled) toast.error(error instanceof Error ? error.message : "查询导入状态失败");
      }
      if (!cancelled) timer = setTimeout(poll, 1500);
    }
    poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [jobId]);

  async function upload(file: File) {
    if (uploading) return;
    if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) {
      toast.error("请上传 .pcap、.pcapng 或 .cap 抓包文件");
      return;
    }
    if (file.size > 2 * 1024 * 1024 * 1024) {
      toast.error("单文件不能超过 2 GB");
      return;
    }
    setUploading(true);
    setUploadProgress(0);
    setResult(null);
    try {
      const data = await new Promise<{ jobId: string }>((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/upload/pcap");
        xhr.setRequestHeader("x-filename", encodeURIComponent(file.name));
        xhr.setRequestHeader("Content-Type", "application/octet-stream");
        xhr.upload.onprogress = event => { if (event.lengthComputable) setUploadProgress(Math.round(event.loaded / event.total * 100)); };
        xhr.onload = () => {
          try {
            const body = JSON.parse(xhr.responseText);
            if (xhr.status >= 200 && xhr.status < 300) resolve(body);
            else reject(new Error(body.detail ?? "上传失败"));
          } catch { reject(new Error("服务器响应异常，请重试")); }
        };
        xhr.onerror = () => reject(new Error("上传连接中断，请重试"));
        xhr.send(file);
      });
      localStorage.setItem("melat-import-job", data.jobId);
      setJobProgress({ status: "queued", packets: 0, imported: 0 });
      setJobId(data.jobId);
      toast.success("文件已上传，正在排队解析");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "上传失败");
      setUploading(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="数据导入"
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
        onClick={() => { if (!uploading) inputRef.current?.click(); }}
        className="panel flex cursor-pointer flex-col items-center justify-center gap-3 border-dashed py-14 transition-colors"
        style={dragOver ? { borderColor: "var(--mint)", background: "var(--mint-dim)" } : {}}
      >
        <input
          ref={inputRef}
          type="file"
          disabled={uploading}
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) upload(f);
            e.target.value = "";
          }}
        />
        <UploadCloud className="h-10 w-10" style={{ color: "var(--mint)" }} />
        <div className="text-sm text-neutral-800">
          {uploading ? (jobId ? (jobProgress.status === "queued" ? "排队等待解析…" : `解析导入中：${jobProgress.packets.toLocaleString()} 个报文，已入库 ${jobProgress.imported.toLocaleString()} 条会话`) : `文件上传中 ${uploadProgress}%`) : "拖拽 pcap 文件到此处，或点击选择文件"}
        </div>
        <div className="text-xs text-neutral-500">
          支持 PCAP / PCAPNG、IPv4 / IPv6，自动解析 DNS、TLS、HTTP 等协议 · 单文件 ≤ 2 GB；上传后后台处理，可刷新查看进度
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
                className="flex items-center gap-1.5 rounded-md px-3.5 py-2 text-xs font-medium text-white disabled:opacity-50"
                style={{ background: "var(--mint)" }}
              >
                <Zap className="h-3.5 w-3.5" /> {runAll.isPending ? "分析中…" : "运行全量分析"}
              </button>
              <Link
                to="/sessions"
                className="flex items-center gap-1.5 rounded-md border px-3.5 py-2 text-xs text-neutral-700"
                style={{ borderColor: "var(--line)" }}
              >
                查看会话 <ArrowRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>
          {!!result.normalizedTimestamps && (
            <p className="mt-3 text-sm text-amber-700" role="status">
              已规范化 {result.normalizedTimestamps.toLocaleString()} 条异常时间戳；涉及时间的分析结果请结合原始抓包核验。
            </p>
          )}
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
          <div className="mt-3 flex items-center gap-2 text-xs text-neutral-600">
            <span className="micro-label">PROTOCOLS</span>
            {Object.entries(result.protoDist).map(([k, v]) => (
              <span key={k} className="rounded bg-slate-100 px-2 py-0.5">
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
            {batches.data?.rows.map((b) => (
              <tr key={b.id} className="border-t text-xs" style={{ borderColor: "var(--line)" }}>
                <td className="num py-2.5 pr-3" style={{ color: "var(--mint)" }}>#{b.id}</td>
                <td className="py-2.5 pr-3 text-neutral-800">{decodeURIComponent(b.filename)}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-600">{fmtBytes(b.sizeBytes)}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-700">{b.packets.toLocaleString()}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-700">{b.flows}</td>
                <td className="num py-2.5 pr-3 text-right text-neutral-600">{b.durationMs}ms</td>
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
            {batches.data?.rows.length === 0 && (
              <tr><td colSpan={8} className="py-8 text-center text-xs text-neutral-500">尚未接入过 pcap 数据</td></tr>
            )}
          </tbody>
        </table>
        <ListPagination label="接入批次" page={page} total={batches.data?.total} onPageChange={setPage} loading={batches.isFetching} />
      </div>
    </div>
  );
}
