# ── 阶段一：构建前端 ────────────────────────────────
FROM node:20-slim AS fe
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# ── 阶段二：Python 运行时（FastAPI 后端 + 前端静态文件） ──
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY db/init.sql ./db/init.sql
COPY .env* ./
COPY --from=fe /app/dist/public ./dist/public

ENV NODE_ENV=production
EXPOSE 3000
# DATABASE_URL 通过 -e 注入：mysql://user:pass@host:3306/dbname
CMD ["python3", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "3000"]
