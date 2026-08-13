#!/usr/bin/env node

import { spawn } from "node:child_process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const device = process.env.CODEX_HOOK_DEVICE || "192.168.2.73:5555";
const toolboxPackage = "com.codex.hooktoolbox";
const validPackage = /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+$/;
const sources = ["all", "java", "conscrypt", "boringssl", "http"];
let controlsAuthorized = false;

const server = new McpServer(
  { name: "codex-hook-toolbox", version: "1.0.10" },
  { instructions: "使用本服务器控制已连接 Android 设备上的 Codex Hook 工具箱。先 probe 或 list_apps 确认目标包名。默认只读；执行任何控制操作或 Android Shell 前，必须先在当前对话征得用户同意并调用 authorize_controls(confirmed=true)。授权只在当前 MCP 进程内有效，重启或新会话自动恢复只读。device_shell 仅在已配置 Android 设备运行，绝不在宿主机执行。" }
);

function ensurePackage(packageName) {
  if (!validPackage.test(packageName) || packageName.length > 190) {
    throw new Error("包名格式无效");
  }
  return packageName;
}

function textResult(value, isError = false) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text }], isError };
}

function requireControls() {
  if (!controlsAuthorized) {
    throw new Error("MCP 当前为只读：必须先征得用户同意，再调用 authorize_controls 并传 confirmed=true。");
  }
}

function run(command, args, timeoutMs = 30000, input = "") {
  return new Promise((resolve) => {
    const child = spawn(command, args, { stdio: [input ? "pipe" : "ignore", "pipe", "pipe"] });
    let output = "";
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk) => { output += chunk; });
    child.stderr.on("data", (chunk) => { output += chunk; });
    child.on("error", (error) => { output += error.message; });
    if (input) child.stdin.end(input);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ ok: code === 0 && !timedOut, code, output: output.trim(), timedOut });
    });
  });
}

async function adb(args, timeoutMs) {
  const result = await run("adb", ["-s", device, ...args], timeoutMs);
  if (!result.ok) throw new Error(result.output || "adb 操作失败");
  return result.output;
}

async function root(script, timeoutMs = 30000) {
  const result = await run("adb", ["-s", device, "shell", "su", "0", "sh"], timeoutMs, `${script}\nexit\n`);
  if (!result.ok) throw new Error(result.output || "root shell 操作失败");
  return result.output;
}

async function packageUid(packageName) {
  const output = await adb(["shell", "cmd", "package", "list", "packages", "-U", packageName]);
  const match = output.match(/uid:(\d+)/);
  if (!match) throw new Error("目标应用未安装");
  return Number(match[1]);
}

async function toolApps() {
  const output = await adb(["shell", "cmd", "package", "list", "packages", "-3"]);
  const packages = output.split("\n").map((line) => line.replace(/^package:/, "")).filter(Boolean);
  const apps = [];
  for (const packageName of packages) {
    const [label, uid] = await Promise.all([
      adb(["shell", "cmd", "package", "resolve-activity", "--brief", packageName]).catch(() => ""),
      packageUid(packageName).catch(() => null)
    ]);
    apps.push({ packageName, label: label.trim() || packageName, uid });
  }
  return apps;
}

async function toolProbe(packageName) {
  ensurePackage(packageName);
  const uid = await packageUid(packageName);
  const files = `/sdcard/Android/data/${packageName}/files`;
  const script = [
    "kv(){ printf '%s=%s\\n' \"$1\" \"$2\"; }",
    `kv package ${packageName}`,
    `kv uid ${uid}`,
    "kv root_uid \"$(id -u)\"",
    `kv process_count \"$(ps -A -o NAME 2>/dev/null | awk -v p=${shellQuote(packageName)} '$1==p || index($1,p \":\")==1 {n++} END{print n+0}')\"`,
    "kv trace_state \"$(cat /proc/pine_syscall_trace 2>/dev/null | tr '\\n' ';')\"",
    "kv art_debug \"$(getprop debug.pine.art_dexdump)\"",
    "kv art_debug_pkg \"$(getprop debug.pine.art_dexdump_pkg)\"",
    "kv art_persist \"$(getprop persist.sys.pine_art_dexdump)\"",
    "kv art_persist_pkg \"$(getprop persist.sys.pine_art_dexdump_pkg)\"",
    `kv hot_enabled \"$([ -f ${shellQuote(`${files}/dandelion-hot.enable`)} ] && echo 1 || echo 0)\"`,
    ...["java-crypto.log", "conscrypt-crypto.log", "boringssl-crypto.log", "http-network.log"].map((name) =>
      `kv ${name.replace(/[^a-z]/g, "_")}_bytes \"$(stat -c %s ${shellQuote(`${files}/dandelion-hot-dumps/${name}`)} 2>/dev/null || echo 0)\"`)
  ].join("\n");
  return parseKeyValues(await root(script));
}

function shellQuote(value) {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function parseKeyValues(value) {
  return Object.fromEntries(value.split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return index > 0 ? [line.slice(0, index), line.slice(index + 1)] : [line, ""];
  }));
}

async function toggleHot(packageName, enabled) {
  ensurePackage(packageName);
  const files = `/sdcard/Android/data/${packageName}/files`;
  const marker = `${files}/dandelion-hot.enable`;
  const stopped = `${files}/dandelion-hot.stopped`;
  const script = enabled
    ? `find /sdcard/Android/data -path '*/files/dandelion-hot.enable' -type f 2>/dev/null | while IFS= read -r old; do rm -f "$old"; done; mkdir -p ${shellQuote(`${files}/dandelion-hot-dumps`)}; printf 'package=%s\\n' ${shellQuote(packageName)} > ${shellQuote(marker)}; rm -f ${shellQuote(stopped)}; chmod 0777 ${shellQuote(`${files}/dandelion-hot-dumps`)}; chmod 0666 ${shellQuote(marker)}`
    : `rm -f ${shellQuote(marker)}; date +%s > ${shellQuote(stopped)}; chmod 0666 ${shellQuote(stopped)}`;
  await root(script);
  return toolProbe(packageName);
}

async function toggleArt(packageName, enabled) {
  ensurePackage(packageName);
  const uid = enabled ? await packageUid(packageName) : 0;
  const script = enabled
    ? `out=/data/temp/pine-art-dumps/${packageName}; cache=/data/user/0/${packageName}/cache; mkdir -p /data/temp/pine-art-dumps "$out"; ctx=$(ls -Zd "$cache" 2>/dev/null | awk '{print $1}'); chown ${uid}:${uid} "$out"; chmod 0700 "$out"; [ -z "$ctx" ] || chcon "$ctx" "$out"; setprop persist.sys.pine_art_dexdump_pkg ${shellQuote(packageName)}; setprop persist.sys.pine_art_dexdump true; setprop debug.pine.art_dexdump_pkg ${shellQuote(packageName)}; setprop debug.pine.art_dexdump 1`
    : "setprop debug.pine.art_dexdump 0; setprop debug.pine.art_dexdump_pkg __disabled__; setprop persist.sys.pine_art_dexdump false; setprop persist.sys.pine_art_dexdump_pkg __disabled__; rm -f /data/temp/pine-art-dump.enable /data/temp/pine-art-dump.pkg";
  await root(script);
  return toolProbe(packageName);
}

async function setLive(packageName, enabled, floating) {
  ensurePackage(packageName);
  if (!enabled) {
    await adb(["shell", "am", "stopservice", "-n", `${toolboxPackage}/.LiveCaptureService`]);
    return { ok: true, running: false };
  }
  await adb(["shell", "am", "start-foreground-service", "-n", `${toolboxPackage}/.LiveCaptureService`, "--es", "packageName", packageName, "--ez", "floating", String(Boolean(floating))]);
  return { ok: true, running: true, packageName, floating: Boolean(floating) };
}

async function readEvents(packageName, source, limit, includeNoise) {
  ensurePackage(packageName);
  if (!sources.includes(source)) throw new Error("日志来源无效");
  const names = source === "all"
    ? ["java-crypto.log", "conscrypt-crypto.log", "boringssl-crypto.log", "http-network.log"]
    : [{ java: "java-crypto.log", conscrypt: "conscrypt-crypto.log", boringssl: "boringssl-crypto.log", http: "http-network.log" }[source]];
  const rootPath = `/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps`;
  const events = [];
  for (const name of names) {
    const output = await root(`tail -c 262144 ${shellQuote(`${rootPath}/${name}`)} 2>/dev/null || true`);
    for (const block of output.split(/(?=^event=)/m)) {
      const fields = parseKeyValues(block);
      if (!fields.event) continue;
      const event = { source: name, event: fields.event, direction: fields.direction || "unknown", fields: {}, payloads: [] };
      for (const [key, value] of Object.entries(fields)) {
        if (key.endsWith("_hex") && /^[0-9a-f\s]+$/i.test(value)) {
          const decoded = decodeHex(value, Object.values(fields).join(" "));
          event.payloads.push({ field: key, ...decoded });
        } else if (!key.endsWith("_hex")) event.fields[key] = value;
      }
      const lowered = event.event.toLowerCase();
      event.metadata = lowered.startsWith("socket.send") || lowered.startsWith("socket.recv");
      event.noise = lowered.includes("digest") || lowered.includes("hmac") || lowered.startsWith("mac.");
      if ((event.metadata || event.noise) && !includeNoise) continue;
      events.push(event);
    }
  }
  return { packageName, source, events: events.slice(-Math.max(1, Math.min(limit, 120))).reverse() };
}

function decodeHex(rawHex, hints) {
  const raw = rawHex.replace(/[^0-9a-f]/gi, "").slice(0, 262144);
  const data = Buffer.from(raw.length % 2 ? raw.slice(0, -1) : raw, "hex");
  const text = data.toString("utf8");
  const utf8 = Buffer.from(text, "utf8").equals(data);
  if (!utf8 || /[\x00-\x08\x0b\x0c\x0e-\x1f]/.test(text)) return { rawHex: raw, text: "", encoding: "binary/ciphertext", binary: true };
  let formatted = text;
  try { formatted = JSON.stringify(JSON.parse(text), null, 2); } catch {}
  return { rawHex: raw, text: formatted, encoding: formatted === text ? "UTF-8" : "json / UTF-8", binary: false };
}

async function startTrace(packageName, scope, duration) {
  ensurePackage(packageName);
  const seconds = Math.max(3, Math.min(30, duration));
  const uid = scope === "pid"
    ? (await root(`for p in /proc/[0-9]*; do n=$(tr '\\0' '\\n' <\"$p/cmdline\" 2>/dev/null | head -n1); [ \"$n\" = ${shellQuote(packageName)} ] && { basename \"$p\"; break; }; done`)).trim()
    : String(await packageUid(packageName));
  if (!/^\d+$/.test(uid)) throw new Error("无法解析 Trace 目标");
  await root(`[ -w /proc/pine_syscall_trace ] || exit 2; printf '${scope === "pid" ? "pid" : "uid"} ${uid}\\n' > /proc/pine_syscall_trace; cat /proc/pine_syscall_trace`);
  setTimeout(() => root("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true").catch(() => {}), seconds * 1000).unref();
  return { ok: true, packageName, scope: `${scope === "pid" ? "pid" : "uid"} ${uid}`, duration: seconds, note: "Trace 已启动；请在结束前调用 trace_stop，最长 30 秒" };
}

async function exportArtifacts(packageName, type) {
  ensurePackage(packageName);
  const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
  const rootPath = `/sdcard/Download/CodexHookToolbox`;
  const stage = `/data/local/tmp/codex-hook-export-${process.pid}`;
  const archive = `${rootPath}/${packageName}-${type}-${stamp}.zip`;
  let script;
  if (type === "logs") {
    const source = `/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps`;
    script = `rm -rf ${shellQuote(stage)}; mkdir -p ${shellQuote(`${stage}/raw`)} ${shellQuote(rootPath)}; for n in java-crypto.log conscrypt-crypto.log boringssl-crypto.log http-network.log; do f=${shellQuote(source)}/\"$n\"; [ -f \"$f\" ] && tail -c 16777216 \"$f\" > ${shellQuote(`${stage}/raw`)}/\"$n\"; done; printf 'package=%s\\nkind=logs\\nraw_preserved=true\\n' ${shellQuote(packageName)} > ${shellQuote(`${stage}/manifest.txt`)}; cd ${shellQuote(stage)} && zip -qr ${shellQuote(archive)} .; sha256sum ${shellQuote(archive)}; rm -rf ${shellQuote(stage)}`;
  } else if (type === "dex") {
    const source = `/data/temp/pine-art-dumps/${packageName}`;
    script = `rm -rf ${shellQuote(stage)}; mkdir -p ${shellQuote(`${stage}/dex`)} ${shellQuote(rootPath)}; for f in ${shellQuote(source)}/*.dex ${shellQuote(source)}/*.cdex; do [ -f \"$f\" ] || continue; h=\$(sha256sum \"$f\" | awk '{print $1}'); case \"$f\" in *.cdex) e=cdex;; *) e=dex;; esac; cp -f \"$f\" ${shellQuote(`${stage}/dex`)}/\"$h.$e\"; [ ! -f \"$f.meta\" ] || cp -f \"$f.meta\" ${shellQuote(`${stage}/dex`)}/\"$h.$e.meta\"; done; printf 'package=%s\\nkind=dex\\ndedup=sha256\\n' ${shellQuote(packageName)} > ${shellQuote(`${stage}/manifest.txt`)}; cd ${shellQuote(stage)} && zip -qr ${shellQuote(archive)} .; sha256sum ${shellQuote(archive)}; rm -rf ${shellQuote(stage)}`;
  } else if (type === "so") {
    script = `rm -rf ${shellQuote(stage)}; mkdir -p ${shellQuote(`${stage}/maps`)} ${shellQuote(`${stage}/disk`)} ${shellQuote(`${stage}/memory`)} ${shellQuote(rootPath)}; count=0; for p in /proc/[0-9]*; do n=$(tr '\\0' '\\n' <"$p/cmdline" 2>/dev/null | head -n1); case "$n" in ${packageName}|${packageName}:*) ;; *) continue;; esac; pid=$(basename "$p"); count=$((count+1)); maps=${shellQuote(`${stage}/maps`)}/pid-"$pid".maps; cat "$p/maps" > "$maps" 2>/dev/null || continue; awk '$6 ~ /\\.so$/ && $2 ~ /^r/ {print $6}' "$maps" | sort -u | while IFS= read -r f; do case "$f" in */data/data/${packageName}/*|*/data/user/0/${packageName}/*) h=$(printf %s "$f" | sha256sum | awk '{print $1}'); name=$(basename "$f"); cp -f "$f" ${shellQuote(`${stage}/disk`)}/"$h"-"$name" 2>/dev/null || true;; esac; done; mem=0; awk '$6 ~ /\\.so$/ && $2 ~ /^r/ && $2 ~ /x/ && $3 == "00000000" {print $1}' "$maps" | while IFS= read -r range; do [ "$mem" -lt 16 ] || break; start=$(printf %s "$range" | cut -d- -f1); end=$(printf %s "$range" | cut -d- -f2); len=$((0x$end-0x$start)); [ "$len" -gt 0 ] && [ "$len" -le 67108864 ] || continue; magic=$(dd if="$p/mem" bs=4 skip=$((0x$start)) count=1 iflag=skip_bytes status=none 2>/dev/null | od -An -tx1 | tr -d ' \\n'); [ "$magic" = 7f454c46 ] || continue; dd if="$p/mem" of=${shellQuote(`${stage}/memory`)}/pid-"$pid"-"$start".so bs=4096 skip=$((0x$start)) count="$len" iflag=skip_bytes,count_bytes status=none 2>/dev/null || true; mem=$((mem+1)); done; done; printf 'package=%s\\nkind=so\\nprocesses=%s\\ndisk=disk/\\nmemory=memory/\\nmaps=maps/\\n' ${shellQuote(packageName)} "$count" > ${shellQuote(`${stage}/manifest.txt`)}; cd ${shellQuote(stage)} && zip -qr ${shellQuote(archive)} .; sha256sum ${shellQuote(archive)}; rm -rf ${shellQuote(stage)}`;
  } else {
    throw new Error("导出类型无效");
  }
  const output = await root(script, 120000);
  return { ok: true, packageName, type, path: archive, sha256: output.match(/[a-f0-9]{64}/i)?.[0] || "" };
}

async function stopAll(packageName) {
  ensurePackage(packageName);
  await adb(["shell", "am", "stopservice", "-n", `${toolboxPackage}/.LiveCaptureService`]);
  await root(`[ ! -w /proc/pine_syscall_trace ] || printf '0\\n' > /proc/pine_syscall_trace; rm -f ${shellQuote(`/sdcard/Android/data/${packageName}/files/dandelion-hot.enable`)} /data/temp/pine-art-dump.enable /data/temp/pine-art-dump.pkg; setprop debug.pine.art_dexdump 0; setprop debug.pine.art_dexdump_pkg __disabled__; setprop persist.sys.pine_art_dexdump false; setprop persist.sys.pine_art_dexdump_pkg __disabled__`);
  return toolProbe(packageName);
}

server.registerTool("control_status", { title: "读取 MCP 控制授权状态", description: "读取当前 MCP 会话是否已获得用户同意执行控制动作。", inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false } }, async () => textResult({ controlsAuthorized }));
server.registerTool("authorize_controls", { title: "授权本会话全部控制能力", description: "仅在用户已明确同意后调用。授权当前 MCP 会话执行工具箱控制动作和 Android Shell，重启服务或新会话后自动失效。", inputSchema: { confirmed: z.boolean() }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: true } }, async ({ confirmed }) => {
  if (!confirmed) return textResult("拒绝授权：必须先在当前对话取得用户明确同意，并传 confirmed=true。", true);
  controlsAuthorized = true;
  return textResult({ ok: true, controlsAuthorized, scope: "当前 MCP 会话内的全部工具箱控制动作与 Android Shell" });
});
server.registerTool("list_apps", { title: "列出用户应用", description: "列出设备上可选的用户安装应用与 UID。", inputSchema: {}, annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false } }, async () => textResult(await toolApps()));
server.registerTool("probe", { title: "读取 ROM 实际基线", description: "读取目标应用的 root、Hot、ART、Trace 与日志状态。", inputSchema: { packageName: z.string() }, annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false } }, async ({ packageName }) => textResult(await toolProbe(packageName)));
server.registerTool("set_hot", { title: "启停 Crypto/HTTP 采集", description: "启用或停止目标应用的 ROM 外置 dandelion-hot Crypto/HTTP 采集。", inputSchema: { packageName: z.string(), enabled: z.boolean() }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName, enabled }) => { requireControls(); return textResult(await toggleHot(packageName, enabled)); });
server.registerTool("set_art", { title: "启停 ART DEX 导出", description: "启用或停止目标应用的 Pine ART 内存 DEX 导出。", inputSchema: { packageName: z.string(), enabled: z.boolean() }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName, enabled }) => { requireControls(); return textResult(await toggleArt(packageName, enabled)); });
server.registerTool("set_live_capture", { title: "控制实时抓包与悬浮窗", description: "启动或停止工具箱实时日志读取；可同时显示悬浮明文窗。", inputSchema: { packageName: z.string(), enabled: z.boolean(), floating: z.boolean().default(false) }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName, enabled, floating }) => { requireControls(); return textResult(await setLive(packageName, enabled, floating)); });
server.registerTool("read_events", { title: "读取实时网络与加密事件", description: "读取目标应用最新 HTTP、Crypto、Conscrypt、BoringSSL 事件和解码正文。", inputSchema: { packageName: z.string(), source: z.enum(sources).default("all"), limit: z.number().int().min(1).max(120).default(40), includeNoise: z.boolean().default(false) }, annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false } }, async ({ packageName, source, limit, includeNoise }) => textResult(await readEvents(packageName, source, limit, includeNoise)));
server.registerTool("launch_target", { title: "启动目标应用", description: "启动目标应用的 Launcher Activity。", inputSchema: { packageName: z.string() }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName }) => { requireControls(); ensurePackage(packageName); await adb(["shell", "monkey", "-p", packageName, "-c", "android.intent.category.LAUNCHER", "1"]); return textResult({ ok: true, packageName }); });
server.registerTool("trace_start", { title: "启动受控 Trace", description: "按目标 UID 或主进程 TGID 启动最多 30 秒的 syscall Trace。", inputSchema: { packageName: z.string(), scope: z.enum(["uid", "pid"]).default("uid"), duration: z.number().int().min(3).max(30).default(5) }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName, scope, duration }) => { requireControls(); return textResult(await startTrace(packageName, scope, duration)); });
server.registerTool("trace_stop", { title: "停止 Trace 并读取结果", description: "立即关闭 syscall Trace 并返回最新内核 Trace 行。", inputSchema: {}, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async () => { requireControls(); await root("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true"); return textResult({ ok: true, trace: await root("cat /proc/pine_syscall_trace 2>/dev/null; dmesg | grep pine_syscall_trace | tail -n 5000") }); });
server.registerTool("export_artifacts", { title: "导出工具箱证据", description: "导出原始日志、内存 DEX 或运行时 SO 证据包到设备 下载/CodexHookToolbox，并返回 SHA256。", inputSchema: { packageName: z.string(), type: z.enum(["logs", "dex", "so"]) }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName, type }) => { requireControls(); return textResult(await exportArtifacts(packageName, type)); });
server.registerTool("stop_all", { title: "停止全部采集", description: "停止实时读取、Hot、ART 与 Trace，并返回目标最终基线。", inputSchema: { packageName: z.string() }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: false } }, async ({ packageName }) => { requireControls(); return textResult(await stopAll(packageName)); });
server.registerTool("device_shell", { title: "在 Android 设备运行 Shell", description: "在当前会话已获用户同意后，在已配置 Android 设备运行 Shell；可选 root 权限，绝不在宿主机执行。", inputSchema: { command: z.string().min(1).max(8000), asRoot: z.boolean().default(false), timeoutSeconds: z.number().int().min(1).max(120).default(30) }, annotations: { readOnlyHint: false, openWorldHint: false, destructiveHint: true } }, async ({ command, asRoot, timeoutSeconds }) => {
  requireControls();
  return textResult({ ok: true, output: asRoot ? await root(command, timeoutSeconds * 1000) : await adb(["shell", "sh", "-c", command], timeoutSeconds * 1000) });
});

await server.connect(new StdioServerTransport());
