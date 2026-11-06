import { useEffect, useState } from "react";

export const PAGE_SIZE = 10;

export function usePageRows<T>(rows: T[], resetKey: unknown = null) {
  const [state, setState] = useState({ page: 1, key: resetKey });
  if (state.key !== resetKey) setState({ page: 1, key: resetKey });
  const page = Math.min(state.key === resetKey ? state.page : 1, Math.max(1, Math.ceil(rows.length / PAGE_SIZE)));
  const setPage = (next: number) => setState({ page: next, key: resetKey });
  return { rows: rows.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE), page, setPage, total: rows.length };
}

export default function ListPagination({ page, total, onPageChange, loading = false, label = "列表" }: {
  page: number; total?: number; onPageChange: (page: number) => void; loading?: boolean; label?: string;
}) {
  const pages = Math.max(1, Math.ceil((total ?? 0) / PAGE_SIZE));
  useEffect(() => {
    if (total !== undefined && page > pages) onPageChange(pages);
  }, [page, pages, total, onPageChange]);
  const buttonClass = "rounded-md border px-2.5 py-1.5 text-xs disabled:cursor-not-allowed disabled:opacity-40 hover:enabled:bg-slate-50";
  return (
    <nav aria-label={`${label}分页`} className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-neutral-600">
      <span aria-live="polite">共 {total ?? "…"} 条 · 每页 {PAGE_SIZE} 条 · 第 {page}/{pages} 页</span>
      <div className="flex gap-2">
        <button type="button" className={buttonClass} disabled={loading || total === undefined || page <= 1} onClick={() => onPageChange(1)}>首页</button>
        <button type="button" className={buttonClass} disabled={loading || total === undefined || page <= 1} onClick={() => onPageChange(page - 1)}>上一页</button>
        <button type="button" className={buttonClass} disabled={loading || total === undefined || page >= pages} onClick={() => onPageChange(page + 1)}>下一页</button>
        <button type="button" className={buttonClass} disabled={loading || total === undefined || page >= pages} onClick={() => onPageChange(pages)}>末页</button>
      </div>
    </nav>
  );
}
