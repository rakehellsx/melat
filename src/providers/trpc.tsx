/**
 * 前端数据访问层（REST 版）
 * 后端为 Python FastAPI（/api/rpc/*），本模块保持与原 tRPC 客户端一致的
 * 调用形态（trpc.<模块>.<方法>.useQuery / useMutation / useUtils），
 * 页面代码无需改动。
 */
import {
  QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient,
} from "@tanstack/react-query";
import type { ReactNode } from "react";

const queryClient = new QueryClient();

async function rpcGet(path: string, input?: unknown) {
  const url = input === undefined || input === null
    ? `/api/rpc/${path}`
    : `/api/rpc/${path}?input=${encodeURIComponent(JSON.stringify(input))}`;
  const res = await fetch(url, { credentials: "include" });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.detail ?? `请求失败（${res.status}）`);
  return data;
}

async function rpcPost(path: string, input: unknown) {
  const res = await fetch(`/api/rpc/${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input ?? {}),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.detail ?? `请求失败（${res.status}）`);
  return data;
}

interface ProcHooks {
  useQuery: (input?: unknown, opts?: Record<string, unknown>) => unknown;
  useMutation: (opts?: Record<string, unknown>) => unknown;
}

function makeProc(path: string): ProcHooks {
  return {
    useQuery: (input?: unknown, opts?: Record<string, unknown>) =>
      useQuery({
        queryKey: [path, input ?? null],
        queryFn: () => rpcGet(path, input),
        ...(opts ?? {}),
      }),
    useMutation: (opts?: Record<string, unknown>) =>
      useMutation({
        mutationFn: (vars: unknown) => rpcPost(path, vars),
        ...(opts ?? {}),
      }),
  };
}

const procCache = new Map<string, ProcHooks>();
const routerCache = new Map<string, unknown>();

function routerProxy(router: string): unknown {
  return new Proxy({}, {
    get(_t, proc: string) {
      const key = `${router}.${proc}`;
      if (!procCache.has(key)) procCache.set(key, makeProc(key));
      return procCache.get(key);
    },
  });
}

function makeUtils() {
  const qc = useQueryClient();
  return new Proxy({}, {
    get(_t, router: string) {
      return new Proxy({}, {
        get(_t2, proc: string) {
          return {
            invalidate: () => qc.invalidateQueries({ queryKey: [`${router}.${proc}`] }),
          };
        },
      });
    },
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const trpc: any = new Proxy({}, {
  get(_t, key: string) {
    if (key === "useUtils") return makeUtils;
    if (!routerCache.has(key)) routerCache.set(key, routerProxy(key));
    return routerCache.get(key);
  },
});

export function TRPCProvider({ children }: { children: ReactNode }) {
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}
