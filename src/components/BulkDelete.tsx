import { useEffect, useRef, useState } from "react";
import {
  AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle,
  AlertDialogDescription, AlertDialogFooter, AlertDialogCancel,
} from "@/components/ui/alert-dialog";

export function useRowSelection(resetKey: string) {
  const [state, setState] = useState<{ key: string; ids: Set<number> }>({ key: resetKey, ids: new Set() });
  if (state.key !== resetKey) setState({ key: resetKey, ids: new Set() });
  const ids = state.key === resetKey ? state.ids : new Set<number>();
  function toggle(id: number) {
    const next = new Set(ids);
    if (next.has(id)) next.delete(id); else next.add(id);
    setState({ key: resetKey, ids: next });
  }
  function togglePage(pageIds: number[]) {
    const next = new Set(ids), all = pageIds.every(id => ids.has(id));
    pageIds.forEach(id => all ? next.delete(id) : next.add(id));
    setState({ key: resetKey, ids: next });
  }
  return { ids, toggle, togglePage, clear: () => setState({ key: resetKey, ids: new Set() }) };
}

export function PageSelection({ ids, selected, onChange, disabled = false }: {
  ids: number[]; selected: Set<number>; onChange: () => void; disabled?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  const count = ids.filter(id => selected.has(id)).length;
  useEffect(() => { if (ref.current) ref.current.indeterminate = count > 0 && count < ids.length; }, [count, ids.length]);
  return <input ref={ref} type="checkbox" aria-label="全选当前页" checked={ids.length > 0 && count === ids.length}
    disabled={disabled || !ids.length} onChange={onChange} className="h-4 w-4 accent-emerald-700" />;
}

export default function BulkDelete({ entity, selectedCount, total, pending, onSelected, onAll }: {
  entity: string; selectedCount: number; total?: number; pending: boolean;
  onSelected: () => Promise<unknown>; onAll: () => Promise<unknown>;
}) {
  const [mode, setMode] = useState<"selected" | "all" | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const button = "rounded-md border px-3 py-2 text-xs text-red-700 disabled:opacity-40 disabled:cursor-not-allowed hover:enabled:bg-red-50";
  async function confirm() {
    try { await (mode === "all" ? onAll() : onSelected()); setMode(null); }
    catch { /* Mutation handlers display the server error and keep the dialog open. */ }
  }
  return <>
    <div className="mb-4 flex flex-wrap items-center gap-3">
      <span className="text-xs text-neutral-600">已选择 {selectedCount} 条（支持跨页选择）</span>
      <button type="button" className={button} disabled={pending || !selectedCount} onClick={() => { setMode("selected"); setConfirmation(""); }}>批量删除</button>
      <button type="button" className={button} disabled={pending || total === undefined} onClick={() => { setMode("all"); setConfirmation(""); }}>全部删除</button>
    </div>
    <AlertDialog open={mode !== null} onOpenChange={open => { if (!open && !pending) setMode(null); }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{mode === "all" ? `删除全部${entity}` : `删除已选${entity}`}</AlertDialogTitle>
          <AlertDialogDescription>{mode === "all"
            ? `将删除全部${entity}数据，包括其他页和当前筛选条件以外的数据。删除后无法恢复，请输入“删除全部”确认。`
            : `将删除已选的 ${selectedCount} 条${entity}记录，包括其他页中已选择的数据。删除后无法恢复。`}</AlertDialogDescription>
        </AlertDialogHeader>
        {mode === "all" && <input autoComplete="off" aria-label="删除确认文字" value={confirmation} onChange={e => setConfirmation(e.target.value)} placeholder="请输入 删除全部" className="rounded border px-3 py-2 text-sm" />}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>取消</AlertDialogCancel>
          <button type="button" disabled={pending || (mode === "all" && confirmation !== "删除全部")} onClick={confirm}
            className="rounded-md bg-red-700 px-4 py-2 text-sm text-white disabled:opacity-40">{pending ? "删除中…" : "确认删除"}</button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  </>;
}
