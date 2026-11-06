/**
 * 平台部署入口（node dist/boot.js）
 * 平台运行时仅支持 Node 启动，本脚本负责拉起 Python FastAPI 后端
 * （uvicorn 监听内部端口），并将外部流量透明转发给它。
 * Python 依赖已 vendored 在 pylibs/（纯 Python + abi 兼容 wheel），
 * 若 vendored 依赖与运行时 Python 版本不匹配，自动尝试 pip 安装兜底。
 */
import { spawn, spawnSync } from "child_process";
import http from "http";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.dirname(fileURLToPath(import.meta.url)); // dist/
const APP = path.resolve(ROOT, "..");
const PYLIBS = path.join(APP, "pylibs");
const RT_PYLIBS = "/tmp/rt_pylibs";
const INTERNAL_PORT = 3001;
const PUBLIC_PORT = parseInt(process.env.PORT || "3000", 10);
const PY_BINS = [path.join(APP, ".venv", "bin", "python"), "python3.12", "python3.13", "python3.11", "python3.10", "python3", "python"];

function testImports(bin: string, pythonpath: string): boolean {
  const r = spawnSync(bin, ["-c", "import fastapi, uvicorn, pyshark"], {
    encoding: "utf8",
    env: { ...process.env, PYTHONPATH: pythonpath },
  });
  if (r.error || r.status !== 0) {
    console.log(`[boot] ${bin} 导入 vendored 依赖失败: ${(r.stderr || String(r.error)).slice(-400)}`);
    return false;
  }
  return true;
}

function resolvePython(): { bin: string; pythonpath: string } | null {
  const existing: string[] = [];
  for (const bin of PY_BINS) {
    const v = spawnSync(bin, ["-c", "import sys; print(sys.version.split()[0])"], { encoding: "utf8" });
    if (v.error || v.status !== 0) continue;
    existing.push(bin);
    console.log(`[boot] 发现 ${bin} (${v.stdout.trim()})`);
    if (testImports(bin, PYLIBS)) return { bin, pythonpath: PYLIBS };
  }
  if (existing.length === 0) return null;
  // vendored 依赖 ABI 不匹配 → 尝试用当前 Python 现场安装
  const bin = existing[0];
  console.log(`[boot] vendored 依赖不匹配，尝试 pip 安装到 ${RT_PYLIBS} ...`);
  const pip = spawnSync(
    bin,
    ["-m", "pip", "install", "--quiet", "--target", RT_PYLIBS, "--only-binary=:all:", "fastapi", "uvicorn", "pyshark==0.6"],
    { encoding: "utf8", timeout: 180_000 }
  );
  if (!pip.error && pip.status === 0 && testImports(bin, RT_PYLIBS)) {
    return { bin, pythonpath: RT_PYLIBS };
  }
  console.log(`[boot] pip 兜底失败: ${(pip.stderr || String(pip.error)).slice(-400)}`);
  return null;
}

function startBackend(bin: string, pythonpath: string) {
  const child = spawn(
    bin,
    ["-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", String(INTERNAL_PORT)],
    { cwd: APP, env: { ...process.env, PYTHONPATH: pythonpath }, stdio: "inherit" }
  );
  child.on("exit", (code) => {
    console.log(`[boot] python 后端退出(code=${code})，3s 后重启`);
    setTimeout(() => startBackend(bin, pythonpath), 3000);
  });
}

async function waitReady(timeoutMs = 60_000): Promise<boolean> {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    const ok = await new Promise<boolean>((resolve) => {
      const req = http.get(`http://127.0.0.1:${INTERNAL_PORT}/api/rpc/meta.fieldCatalog`, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on("error", () => resolve(false));
      req.setTimeout(3000, () => req.destroy());
    });
    if (ok) return true;
    await new Promise((r) => setTimeout(r, 800));
  }
  return false;
}

function startProxy() {
  const server = http.createServer((req, res) => {
    const preq = http.request(
      {
        host: "127.0.0.1",
        port: INTERNAL_PORT,
        path: req.url,
        method: req.method,
        headers: { ...req.headers, host: `127.0.0.1:${INTERNAL_PORT}` },
      },
      (pres) => {
        res.writeHead(pres.statusCode ?? 502, pres.headers);
        pres.pipe(res);
      }
    );
    preq.on("error", () => {
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ detail: "backend starting, retry shortly" }));
    });
    req.pipe(preq);
  });
  server.listen(PUBLIC_PORT, () => {
    console.log(`[boot] 代理已监听 :${PUBLIC_PORT} → 127.0.0.1:${INTERNAL_PORT}`);
  });
}

const py = resolvePython();
if (!py) {
  console.error("[boot] 未找到可用的 Python 运行时");
  console.error(`[boot] node=${process.version} platform=${process.platform}/${process.arch}`);
  try {
    const bins = (await import("fs")).readdirSync("/usr/bin").filter((f) => f.startsWith("python"));
    console.error(`[boot] /usr/bin python*: ${bins.join(", ") || "(none)"}`);
  } catch {}
  process.exit(1);
}

startBackend(py.bin, py.pythonpath);
if (await waitReady()) {
  console.log("[boot] Python 后端已就绪");
} else {
  console.log("[boot] 后端就绪等待超时，仍继续启动代理（请求将重试）");
}
startProxy();
