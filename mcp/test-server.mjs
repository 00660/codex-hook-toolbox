import assert from "node:assert/strict";
import { spawn } from "node:child_process";

const child = spawn(process.execPath, ["mcp/server.mjs"], { stdio: ["pipe", "pipe", "pipe"] });
let nextId = 0;
const pending = new Map();
let buffer = "";
child.stdout.on("data", (chunk) => {
  buffer += chunk;
  for (;;) {
    const index = buffer.indexOf("\n");
    if (index < 0) break;
    const line = buffer.slice(0, index);
    buffer = buffer.slice(index + 1);
    if (!line) continue;
    const message = JSON.parse(line);
    const resolve = pending.get(message.id);
    if (resolve) { pending.delete(message.id); resolve(message); }
  }
});

function call(method, params) {
  const id = ++nextId;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve, reject) => {
    pending.set(id, resolve);
    setTimeout(() => reject(new Error(method + " timeout")), 5000);
  });
}

try {
  const initialized = await call("initialize", { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" } });
  assert.equal(initialized.result.serverInfo.name, "codex-hook-toolbox");
  const listed = await call("tools/list", {});
  const names = listed.result.tools.map((tool) => tool.name);
  for (const name of ["control_status", "authorize_controls", "list_apps", "probe", "set_hot", "set_art", "set_live_capture", "read_events", "launch_target", "trace_start", "trace_stop", "export_artifacts", "stop_all", "device_shell"]) assert(names.includes(name));
  const shell = await call("tools/call", { name: "device_shell", arguments: { command: "id" } });
  assert.equal(shell.result.isError, true);
  assert.match(shell.result.content[0].text, /只读/);
  const denied = await call("tools/call", { name: "authorize_controls", arguments: { confirmed: false } });
  assert.equal(denied.result.isError, true);
  assert.match(denied.result.content[0].text, /confirmed=true/);
  const granted = await call("tools/call", { name: "authorize_controls", arguments: { confirmed: true } });
  assert.equal(JSON.parse(granted.result.content[0].text).controlsAuthorized, true);
  const status = await call("tools/call", { name: "control_status", arguments: {} });
  assert.equal(JSON.parse(status.result.content[0].text).controlsAuthorized, true);
  console.log("MCP 协议和工具注册校验通过");
} finally {
  child.kill("SIGTERM");
}
