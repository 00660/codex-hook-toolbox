import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const device = process.env.CODEX_HOOK_DEVICE || "192.168.2.73:5555";
const packageName = "com.codex.hooktoolbox";
const path = `/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps/http-network.log`;
const request = JSON.stringify({ msg: "请求中文显文", note: "发送体验" });
const response = JSON.stringify({ msg: "回包中文显文", 商品: "测试商品" });
const block = [
  "event=Codex.mcp.request", "time_ms=1786587000123", "direction=outbound",
  `request_body_hex=${Buffer.from(request, "utf8").toString("hex")}`, "---",
  "event=Codex.mcp.response", "time_ms=1786587001123", "direction=inbound",
  `response_body_hex=${Buffer.from(response, "utf8").toString("hex")}`, "---", ""
].join("\n");

async function run(command, args) {
  const process = (await import("node:child_process")).spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  process.stdout.on("data", (chunk) => { output += chunk; });
  process.stderr.on("data", (chunk) => { output += chunk; });
  const code = await new Promise((resolve) => process.on("close", resolve));
  if (code !== 0) throw new Error(output);
  return output.trim();
}

const escaped = block.replace(/'/g, "'\\''");
await run("adb", ["-s", device, "shell", "su", "-c", `rm -rf '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'; mkdir -p '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'; printf '%s' '${escaped}' > '${path}'`]);

const client = new Client({ name: "device-json-test", version: "1" });
const transport = new StdioClientTransport({ command: process.execPath, args: ["mcp/server.mjs"], stderr: "pipe" });
try {
  await client.connect(transport);
  const result = await client.callTool({ name: "read_events", arguments: {
    packageName, source: "http", limit: 120, includeNoise: true
  } });
  const events = JSON.parse(result.content[0].text).events;
  const requestEvent = events.find((event) => event.event === "Codex.mcp.request");
  const responseEvent = events.find((event) => event.event === "Codex.mcp.response");
  assert.equal(requestEvent.direction, "outbound");
  assert.equal(responseEvent.direction, "inbound");
  assert.equal(JSON.parse(requestEvent.payloads[0].text).msg, "请求中文显文");
  assert.equal(JSON.parse(requestEvent.payloads[0].text).note, "发送体验");
  assert.equal(JSON.parse(responseEvent.payloads[0].text).msg, "回包中文显文");
  assert.equal(JSON.parse(responseEvent.payloads[0].text).商品, "测试商品");
  assert.equal(requestEvent.payloads[0].encoding, "json / UTF-8");
  assert.equal(responseEvent.payloads[0].encoding, "json / UTF-8");
  console.log("MCP 真机双向 UTF-8 JSON 读取校验通过");
} finally {
  await client.close().catch(() => {});
  await run("adb", ["-s", device, "shell", "su", "-c", `rm -rf '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'`]);
}
