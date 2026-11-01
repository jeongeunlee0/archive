"use strict";
/*
 * 나의 수업 아카이브 · 로컬 서버
 * - index.html 을 http://localhost 로 열어 주고
 * - .env 의 API 키로 Claude · ChatGPT 요청을 대신 보내 줍니다 (키는 브라우저로 전달되지 않음)
 *
 * 필요: Node.js 18 이상 (외부 패키지 설치 없음)
 * 실행: start.bat 더블클릭 또는  node server.js --open
 */
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { Readable } = require("stream");
const { exec, spawn } = require("child_process");

const ROOT = __dirname;
const APP_ID = "jnu-ai-bootcamp-archive";
loadEnv(path.join(ROOT, ".env"));

const PORT = Number(process.env.PORT) || 5174;
const HOST = "127.0.0.1";
const CFG = {
  anthropic: {
    key: env("ANTHROPIC_API_KEY"),
    base: (env("ANTHROPIC_BASE_URL") || "https://api.anthropic.com").replace(/\/+$/, ""),
    version: env("ANTHROPIC_VERSION") || "2026-10-21",
    model: env("CLAUDE_MODEL") || "claude-opus-5-5",
  },
  openai: {
    key: env("OPENAI_API_KEY"),
    base: (env("OPENAI_BASE_URL") || "https://api.openai.com").replace(/\/+$/, ""),
    model: env("OPENAI_MODEL") || "gpt-5-mini",
  },
};
const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8", ".md": "text/markdown; charset=utf-8", ".txt": "text/plain; charset=utf-8",
  ".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
  ".webp": "image/webp", ".ico": "image/x-icon", ".pdf": "application/pdf", ".woff2": "font/woff2",
};
const MAX_BODY = 25 * 1024 * 1024;
const REA_MAX_BODY = 50 * 1024 * 1024;
const REA_MAX_OUTPUT = 2 * 1024 * 1024;
const REA_TIMEOUT = 45_000;
const PUBLIC_FILES = new Set(["/index.html"]);
// USB 휴대 모드: 이 폴더에 portable.json 이 있으면 USB의 data 폴더가 유일한 원본 (PC 브라우저에는 흔적을 남기지 않음)
const PORTABLE = fs.existsSync(path.join(ROOT, "portable.json"));

function env(k) { return String(process.env[k] || "").trim(); }

// .env 읽기: KEY=VALUE, # 주석, 따옴표 지원. 이미 설정된 시스템 환경변수가 우선
function loadEnv(file) {
  let text;
  try { text = fs.readFileSync(file, "utf8"); } catch { return; }
  for (const raw of text.replace(/^﻿/, "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    else v = v.replace(/\s+#.*$/, "");
    if (!process.env[m[1]]) process.env[m[1]] = v;
  }
}

function send(res, status, body, type = "application/json; charset=utf-8") {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store", "x-content-type-options": "nosniff" });
  res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
const fail = (res, status, message) => send(res, status, { error: { message } });

// 다른 웹사이트가 이 로컬 서버(=내 API 키)를 쓰지 못하도록 막기
function trusted(req) {
  const host = String(req.headers.host || "");
  if (!new RegExp(`^(localhost|127\\.0\\.0\\.1)(:${PORT})?$`).test(host)) return false; // DNS 리바인딩 방지
  const origin = req.headers.origin;
  if (origin) return origin === `http://localhost:${PORT}` || origin === `http://127.0.0.1:${PORT}`;
  const site = req.headers["sec-fetch-site"];
  return !site || site === "same-origin" || site === "none";
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error("요청이 너무 커요 (25MB 초과)"), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function readBuffer(req, max = REA_MAX_BODY) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0, done = false;
    req.on("data", chunk => {
      if (done) return;
      size += chunk.length;
      if (size > max) {
        done = true;
        reject(Object.assign(new Error(`분석 파일이 너무 커요 (${Math.round(max / 1024 / 1024)}MB 초과)`), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => { if (!done) resolve(Buffer.concat(chunks)); });
    req.on("error", e => { if (!done) reject(e); });
  });
}

/* ---------- REA 읽기 전용 분석 연결 ----------
   브라우저가 고른 파일만 운영체제 임시 폴더에 두고, 허용된 REA 명령만 실행한 뒤 즉시 삭제한다. */
const REA_TOOLS = new Set(["triage", "strings", "search", "hexdump", "disasm", "functions", "xrefs", "fn", "apk", "har"]);
const REA_TOOL_LABELS = {
  triage: "정밀 1차 분석", strings: "문자열 추출", search: "바이트 검색", hexdump: "헥스 보기",
  disasm: "디스어셈블", functions: "함수 목록", xrefs: "참조 추적", fn: "함수 전체 보기",
  apk: "APK 구조", har: "HAR API 요약",
};

function executable(name) {
  const ext = process.platform === "win32" ? ".exe" : "";
  const candidates = [
    env("REA_BIN"),
    ...String(process.env.PATH || "").split(path.delimiter).map(p => path.join(p, `${name}${ext}`)),
    process.env.USERPROFILE && path.join(process.env.USERPROFILE, ".local", "bin", `${name}${ext}`),
    "D:\\rea\\.venv\\Scripts\\rea.exe",
  ].filter(Boolean);
  return candidates.find(p => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || "";
}

function cleanFileName(value) {
  const base = path.basename(String(value || "sample.bin")).replace(/[^0-9A-Za-z가-힣._-]/g, "_").slice(-120);
  return base && base !== "." && base !== ".." ? base : "sample.bin";
}

function cleanTarget(value) {
  const target = String(value || "").trim();
  if (!target || target.length > 160 || !/^[0-9A-Za-z._:@$-]+$/.test(target)) return "";
  return target;
}

function boundedInt(value, fallback, min, max) {
  const n = Number(value);
  return Number.isInteger(n) && n >= min && n <= max ? n : fallback;
}

function cleanOffset(value, fallback = "0") {
  const text = String(value || fallback).trim();
  return /^(?:0x[0-9a-f]+|[0-9]+)$/i.test(text) && text.length <= 24 ? text : fallback;
}

function reaArgs(tool, file, query) {
  const json = ["--json"];
  if (tool === "triage" || tool === "apk" || tool === "har") return [tool, file, ...json];
  if (tool === "strings") return [tool, file, "--min-len", "4", "--limit", "200", ...json];
  if (tool === "functions") return [tool, file, "--limit", "200", ...json];
  if (tool === "hexdump") return [tool, file, "--file-offset", cleanOffset(query.get("offset")), "--length", String(boundedInt(query.get("length"), 256, 16, 4096)), ...json];
  if (tool === "disasm") {
    const arch = ["x86", "x64", "arm", "arm64", "mips", "mips64"].includes(query.get("arch")) ? query.get("arch") : "x64";
    return [tool, file, "--arch", arch, "--file-offset", cleanOffset(query.get("offset")), "--count", String(boundedInt(query.get("count"), 64, 1, 400)), ...json];
  }
  if (tool === "search") {
    const pattern = String(query.get("pattern") || "").slice(0, 200);
    const kind = ["text", "utf16", "hex"].includes(query.get("kind")) ? query.get("kind") : "text";
    if (!pattern) throw Object.assign(new Error("검색할 문자열이나 바이트를 입력해 주세요"), { status: 400 });
    return [tool, file, pattern, "--kind", kind, "--limit", "200", ...json];
  }
  const target = cleanTarget(query.get("target"));
  if (!target) throw Object.assign(new Error("함수 이름이나 0x 주소를 입력해 주세요"), { status: 400 });
  if (tool === "xrefs") return [tool, file, target, ...json];
  return ["fn", file, target, "--limit", "400", ...json];
}

function runRea(bin, args, workspace) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin, args, {
      cwd: workspace, shell: false, windowsHide: true,
      env: { ...process.env, REA_WORKSPACE: workspace, PYTHONIOENCODING: "utf-8", NO_COLOR: "1" },
    });
    let stdout = "", stderr = "", settled = false;
    const finish = (err, value) => { if (settled) return; settled = true; clearTimeout(timer); err ? reject(err) : resolve(value); };
    const take = (kind, chunk) => {
      const next = (kind === "out" ? stdout : stderr) + chunk.toString("utf8");
      if (Buffer.byteLength(next) > REA_MAX_OUTPUT) {
        child.kill();
        finish(Object.assign(new Error("분석 결과가 제한을 초과했어요"), { status: 413 }));
      } else if (kind === "out") stdout = next; else stderr = next;
    };
    child.stdout.on("data", c => take("out", c));
    child.stderr.on("data", c => take("err", c));
    child.on("error", e => finish(Object.assign(new Error(`REA를 시작하지 못했어요: ${e.message}`), { status: 503 })));
    child.on("close", code => {
      if (settled) return;
      if (code !== 0) return finish(Object.assign(new Error((stderr || stdout || `REA 종료 코드 ${code}`).trim().slice(0, 1000)), { status: 422 }));
      try { finish(null, JSON.parse(stdout)); }
      catch { finish(Object.assign(new Error("REA 결과 형식을 읽지 못했어요"), { status: 502 })); }
    });
    const timer = setTimeout(() => {
      child.kill();
      finish(Object.assign(new Error(`분석 시간이 ${REA_TIMEOUT / 1000}초를 초과했어요`), { status: 408 }));
    }, REA_TIMEOUT);
  });
}

async function handleRea(req, res, pathname, query) {
  const bin = executable("rea");
  if (pathname === "/api/rea/status" && req.method === "GET") {
    return send(res, 200, { available: !!bin, mode: bin ? "desktop" : "offline", maxBytes: REA_MAX_BODY,
      tools: Object.entries(REA_TOOL_LABELS).map(([id, label]) => ({ id, label })) });
  }
  if (pathname !== "/api/rea/analyze" || req.method !== "POST") return fail(res, 404, "없는 REA 주소");
  if (!bin) return fail(res, 503, "이 PC에는 REA가 없어요. 오프라인 분석을 이용해 주세요");
  const tool = String(query.get("tool") || "triage");
  if (!REA_TOOLS.has(tool)) return fail(res, 400, "허용되지 않은 분석 기능");
  let body;
  try { body = await readBuffer(req); } catch (e) { return fail(res, e.status || 400, e.message); }
  if (!body.length) return fail(res, 400, "분석할 파일이 비어 있어요");
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rea-archive-"));
  const file = path.join(temp, cleanFileName(req.headers["x-file-name"]));
  try {
    fs.writeFileSync(file, body, { flag: "wx" });
    const result = await runRea(bin, reaArgs(tool, file, query), temp);
    if (result && typeof result === "object" && typeof result.file === "string") result.file = cleanFileName(req.headers["x-file-name"]);
    return send(res, 200, { ok: true, tool, label: REA_TOOL_LABELS[tool], result });
  } catch (e) {
    return fail(res, e.status || 500, e.message || "REA 분석 오류");
  } finally {
    try { fs.rmSync(temp, { recursive: true, force: true }); } catch {}
  }
}

/* ---------- 암호화 저장소 (data 폴더) ----------
   브라우저가 PIN으로 암호화한 기록만 받아서 그대로 보관 — 서버는 내용을 읽을 수 없음.
   이 PC의 어느 브라우저로 열어도 같은 기록을 이어서 쓸 수 있게 해 줌. */
const STORE = path.join(ROOT, "data");
const STORE_MAX = 110 * 1024 * 1024;
// 허용된 이름만 (경로 이동 · 임의 파일 쓰기 방지)
const storePath = p => {
  p = String(p || "");
  if (!/^(archive\.json|secrets\.json|README\.txt|수업노트\.md|files\/f[0-9a-z]+(-[0-9a-z]+)?\.bin|files\/f[0-9a-z]+__[^/\\]{1,160})$/.test(p)) return null;
  return path.join(STORE, ...p.split("/"));
};
async function handleStore(req, res, pathname, query) {
  if (pathname === "/api/store/list") {
    const dir = query.get("dir") === "files" ? path.join(STORE, "files") : STORE;
    let names = [];
    try { names = fs.readdirSync(dir, { withFileTypes: true }).filter(e => e.isFile() && !e.name.endsWith(".tmp")).map(e => e.name); } catch {}
    return send(res, 200, { names });
  }
  if (pathname !== "/api/store/file") return fail(res, 404, "없는 API 주소");
  const file = storePath(query.get("path"));
  if (!file) return fail(res, 400, "허용되지 않은 파일 이름");
  if (req.method === "GET") {
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return fail(res, 404, "없는 파일");
      res.writeHead(200, { "content-type": "application/octet-stream", "content-length": st.size, "cache-control": "no-store" });
      fs.createReadStream(file).pipe(res);
    });
    return;
  }
  if (req.method === "PUT" && query.get("path") === "archive.json") {
    // 목록 파일은 작으니 통째로 받아서 확인: 이미 더 최근 기록이 저장돼 있으면 덮어쓰지 않음 (오래 열어 둔 다른 창 · PC 보호)
    let body;
    try { body = await readBody(req); } catch (e) { return fail(res, e.status || 400, e.message); }
    let incoming;
    try { incoming = JSON.parse(body); } catch { return fail(res, 400, "형식이 올바르지 않아요"); }
    let current = null;
    try { current = JSON.parse(fs.readFileSync(file, "utf8")); } catch {}
    // 더 새 버전의 앱이 저장한 기록은 예전 버전 창이 덮어쓰지 못하게 (예전 화면은 새 필드를 모르고 지워 버림)
    const curVer = Number(current?.appVer) || 0, inVer = Number(incoming.appVer) || 0;
    if (current && inVer < curVer) {
      return send(res, 409, { error: { message: "앱이 업데이트됐어요. 새로고침(F5) 후 다시 저장하세요", at: Number(current.at), appVer: curVer, outdated: true } });
    }
    // base(이 창이 마지막으로 본 저장 시각)보다 뒤에 다른 창이 저장했다면 거절. base가 없는 예전 창도 거절해 새로고침을 유도
    const base = Number(incoming.base);
    if (current && (Number(incoming.at) < Number(current.at) || !(Number.isFinite(base) && base >= Number(current.at)))) {
      return send(res, 409, { error: { message: "더 최근 기록이 이미 저장돼 있어요", at: Number(current.at) } });
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    try { fs.writeFileSync(tmp, body); fs.renameSync(tmp, file); }
    catch { try { fs.rmSync(tmp, { force: true }); } catch {} return fail(res, 500, "저장하지 못했어요"); }
    return send(res, 200, { ok: true, size: Buffer.byteLength(body) });
  }
  if (req.method === "PUT") {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    const out = fs.createWriteStream(tmp);
    let size = 0, failed = false;
    req.on("data", c => {
      size += c.length;
      if (size > STORE_MAX && !failed) { failed = true; req.unpipe(out); out.destroy(); fs.rm(tmp, () => {}); fail(res, 413, "파일이 너무 커요"); }
    });
    req.pipe(out);
    out.on("finish", () => {
      if (failed) return;
      // 다 쓴 뒤에 이름을 바꿔서, 쓰는 도중에 끊겨도 이전 파일이 깨지지 않도록
      fs.rename(tmp, file, err => (err ? fail(res, 500, "저장하지 못했어요") : send(res, 200, { ok: true, size })));
    });
    out.on("error", () => { if (!failed) { failed = true; fs.rm(tmp, () => {}); fail(res, 500, "저장하지 못했어요"); } });
    return;
  }
  if (req.method === "DELETE") {
    fs.rm(file, { force: true }, err => (err ? fail(res, 500, "지우지 못했어요") : send(res, 200, { ok: true })));
    return;
  }
  return fail(res, 405, "허용되지 않은 방식");
}

async function relay(res, upstreamUrl, init) {
  const ac = new AbortController();
  res.on("close", () => { if (!res.writableFinished) ac.abort(); }); // 브라우저에서 '중지'하면 AI 요청도 중단
  let up;
  try {
    up = await fetch(upstreamUrl, { ...init, signal: ac.signal });
  } catch (e) {
    if (ac.signal.aborted) return;
    return fail(res, 502, `AI 서버에 연결하지 못했어요: ${e.cause?.code || e.message}`);
  }
  res.writeHead(up.status, {
    "content-type": up.headers.get("content-type") || "application/json",
    "cache-control": "no-store",
    "x-accel-buffering": "no",
  });
  if (!up.body) return res.end();
  Readable.fromWeb(up.body).on("error", () => res.end()).pipe(res);
}

async function handleAI(req, res, provider) {
  const c = CFG[provider];
  if (!c.key) return fail(res, 400, `.env 파일에 ${provider === "anthropic" ? "ANTHROPIC_API_KEY" : "OPENAI_API_KEY"} 값이 없어요`);
  let payload;
  try { payload = JSON.parse(await readBody(req)); } catch (e) { return fail(res, e.status || 400, e.status ? e.message : "요청 형식이 올바르지 않아요"); }
  if (!payload || typeof payload !== "object") return fail(res, 400, "요청 형식이 올바르지 않아요");
  if (!payload.model) payload.model = c.model;
  const headers = { "content-type": "application/json" };
  let url;
  if (provider === "anthropic") {
    url = `${c.base}/v1/messages`;
    headers["x-api-key"] = c.key;
    headers["anthropic-version"] = c.version;
    const beta = req.headers["anthropic-beta"];
    if (beta && /^[a-z0-9\-,\s]+$/i.test(beta)) headers["anthropic-beta"] = beta;
  } else {
    url = `${c.base}/v1/chat/completions`;
    headers.authorization = `Bearer ${c.key}`;
  }
  await relay(res, url, { method: "POST", headers, body: JSON.stringify(payload) });
}

async function handleModels(req, res, provider) {
  const c = CFG[provider];
  if (!c.key) return fail(res, 400, ".env 파일에 API 키가 없어요");
  const headers = provider === "anthropic"
    ? { "x-api-key": c.key, "anthropic-version": c.version }
    : { authorization: `Bearer ${c.key}` };
  await relay(res, `${c.base}/v1/models${provider === "anthropic" ? "?limit=100" : ""}`, { headers });
}

function serveStatic(req, res, pathname) {
  let rel;
  try { rel = decodeURIComponent(pathname); } catch { return fail(res, 400, "잘못된 주소"); }
  if (rel === "/") rel = "/index.html";
  // 앱 화면(index.html)만 제공 — 같은 폴더의 다른 개인 파일 · .env · 하위 폴더는 절대 내보내지 않음
  if (!PUBLIC_FILES.has(rel)) return fail(res, 404, "없는 파일");
  const file = path.normalize(path.join(ROOT, rel));
  if (!file.startsWith(ROOT + path.sep)) return fail(res, 404, "없는 파일");
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) return fail(res, 404, "없는 파일");
    res.writeHead(200, {
      "content-type": MIME[path.extname(file).toLowerCase()] || "application/octet-stream",
      "content-length": st.size,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "cross-origin-opener-policy": "same-origin",
      "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
    });
    if (req.method === "HEAD") return res.end();
    fs.createReadStream(file).pipe(res);
  });
}

const server = http.createServer(async (req, res) => {
  const { pathname, searchParams } = new URL(req.url, `http://${HOST}:${PORT}`);
  try {
    if (pathname.startsWith("/api/")) {
      if (!trusted(req)) return fail(res, 403, "허용되지 않은 요청이에요");
      if (pathname === "/api/health" && req.method === "GET") {
        return send(res, 200, {
          ok: true, app: APP_ID, node: process.version, store: true, portable: PORTABLE,
          providers: {
            anthropic: { configured: !!CFG.anthropic.key, model: CFG.anthropic.model },
            openai: { configured: !!CFG.openai.key, model: CFG.openai.model },
          },
        });
      }
      if (pathname.startsWith("/api/store/")) return await handleStore(req, res, pathname, searchParams);
      if (pathname.startsWith("/api/rea/")) return await handleRea(req, res, pathname, searchParams);
      // USB를 빼기 전에 서버를 끄기 (USB 파일이 사용 중이라 안전하게 제거가 안 되는 문제 방지)
      if (pathname === "/api/shutdown" && req.method === "POST") {
        send(res, 200, { ok: true });
        setTimeout(() => server.close(() => process.exit(0)), 300);
        setTimeout(() => process.exit(0), 2000).unref();
        return;
      }
      const ai = pathname.match(/^\/api\/ai\/(anthropic|openai)$/);
      if (ai && req.method === "POST") return await handleAI(req, res, ai[1]);
      const models = pathname.match(/^\/api\/models\/(anthropic|openai)$/);
      if (models && req.method === "GET") return await handleModels(req, res, models[1]);
      return fail(res, 404, "없는 API 주소");
    }
    if (req.method !== "GET" && req.method !== "HEAD") return fail(res, 405, "허용되지 않은 방식");
    serveStatic(req, res, pathname);
  } catch (e) {
    console.error(e);
    if (!res.headersSent) fail(res, 500, "서버 오류");
    else res.end();
  }
});

function openBrowser(url) {
  const cmd = process.platform === "win32" ? `start "" "${url}"` : process.platform === "darwin" ? `open "${url}"` : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

const major = Number(process.versions.node.split(".")[0]);
if (major < 18) {
  console.error(`Node.js 18 이상이 필요해요 (현재 ${process.version}). https://nodejs.org 에서 LTS 버전을 설치하세요.`);
  process.exit(1);
}

server.on("error", e => {
  if (e.code === "EADDRINUSE") {
    console.log(`\n이미 ${PORT}번 포트에서 서버가 실행 중이에요. 브라우저에서 http://localhost:${PORT} 를 여세요.`);
    if (process.argv.includes("--open")) openBrowser(`http://localhost:${PORT}`);
  } else {
    console.error("서버를 시작하지 못했어요:", e.message);
  }
  process.exitCode = 1;
});

server.listen(PORT, HOST, () => {
  const url = `http://localhost:${PORT}`;
  const mark = ok => (ok ? "연결됨 (.env)" : "키 없음 - .env 에 입력하거나 화면에서 입력");
  console.log("\n  나의 수업 아카이브 · 로컬 서버");
  console.log("  ─────────────────────────────────");
  console.log(`  주소        ${url}`);
  console.log(`  Claude      ${mark(CFG.anthropic.key)}  · 기본 모델 ${CFG.anthropic.model}`);
  console.log(`  ChatGPT     ${mark(CFG.openai.key)}  · 기본 모델 ${CFG.openai.model}`);
  console.log("  종료        이 창을 닫거나 Ctrl + C\n");
  if (process.argv.includes("--open")) openBrowser(url);
});
