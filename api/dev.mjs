/**
 * 开发模式一键启动器（npm run dev）
 * 平台预览只执行 `npm run dev`，而本项目后端是 Python FastAPI，
 * 因此该脚本负责：
 *   1. 拉起 Python 后端（uvicorn，监听 127.0.0.1:3001，供 vite 代理 /api）
 *   2. 启动 vite 开发服务器（对外端口，默认 3000）
 * 任一进程退出则整体退出，交由平台重启。
 */
import { spawn, spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PYLIBS = path.join(ROOT, "pylibs");
const BACKEND_PORT = 3001;
const PUBLIC_PORT = parseInt(process.env.PORT || "3000", 10);
const PY_BINS = [path.join(ROOT, ".venv", "bin", "python"), "python3.12", "python3.13", "python3.11", "python3.10", "python3", "python"];

function resolvePython() {
  for (const bin of PY_BINS) {
    const v = spawnSync(bin, ["-c", "import sys; print(sys.version.split()[0])"], { encoding: "utf8" });
    if (v.error || v.status !== 0) continue;
    const t = spawnSync(bin, ["-c", "import fastapi, uvicorn, pyshark"], {
      encoding: "utf8",
      env: { ...process.env, PYTHONPATH: PYLIBS },
    });
    if (!t.error && t.status === 0) return bin;
    console.log(`[dev] ${bin} 无法导入 pylibs 依赖: ${(t.stderr || "").slice(-300)}`);
  }
  return null;
}

const bin = resolvePython();
if (!bin) {
  console.error("[dev] 未找到可用的 Python 运行时（需要 fastapi/uvicorn/pyshark，见 pylibs/）");
  process.exit(1);
}

const children = [];
function run(name, cmd, args, env = {}) {
  const child = spawn(cmd, args, {
    cwd: ROOT,
    stdio: "inherit",
    env: { ...process.env, ...env },
  });
  child.on("exit", (code) => {
    console.log(`[dev] ${name} 退出(code=${code})，关闭其余进程`);
    for (const c of children) if (c !== child && !c.killed) c.kill("SIGTERM");
    setTimeout(() => process.exit(code ?? 1), 500);
  });
  children.push(child);
  return child;
}

console.log(`[dev] 启动 Python 后端（${bin}）: 127.0.0.1:${BACKEND_PORT}`);
run("backend", bin, [
  "-m", "uvicorn", "backend.main:app",
  "--host", "127.0.0.1", "--port", String(BACKEND_PORT),
], { PYTHONPATH: PYLIBS });

console.log(`[dev] 启动 vite: 0.0.0.0:${PUBLIC_PORT}（/api → 127.0.0.1:${BACKEND_PORT}）`);
const viteBin = path.join(ROOT, "node_modules", ".bin", "vite");
run("vite", viteBin, ["--host", "0.0.0.0", "--port", String(PUBLIC_PORT), "--strictPort"]);
