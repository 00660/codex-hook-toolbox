import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const device = process.env.CODEX_HOOK_DEVICE || "192.168.2.73:5555";
const packageName = "com.codex.hooktoolbox";
const path = `/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps/http-network.log`;
const request = JSON.stringify({ msg: "请求中文显文", note: "发送体验" });
const response = JSON.stringify({ msg: "回包中文显文", 商品: "测试商品" });
const ciphertext = "f8d73a9cff0041b2e5998a7fdc0210";
const block = [
  "event=Codex.mcp.request", "time_ms=1786587000123", "direction=outbound",
  `request_body_hex=${Buffer.from(request, "utf8").toString("hex")}`, "---",
  "event=Codex.mcp.response", "time_ms=1786587001123", "direction=inbound",
  `response_body_hex=${Buffer.from(response, "utf8").toString("hex")}`, "---",
  "event=Cipher.doFinal", "time_ms=1786587002123", `output_hex=${ciphertext}`, "---", ""
].join("\n");

async function run(command, args, input = "") {
  const process = (await import("node:child_process")).spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  process.stdout.on("data", (chunk) => { output += chunk; });
  process.stderr.on("data", (chunk) => { output += chunk; });
  process.stdin.end(input);
  const code = await new Promise((resolve) => process.on("close", resolve));
  if (code !== 0) throw new Error(output);
  return output.trim();
}

async function root(script) {
  return run("adb", ["-s", device, "shell", "su", "0", "sh"], `${script}\nexit\n`);
}

await root(`rm -rf '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'
mkdir -p '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'
cat > '${path}' <<'CODEX_LOG'
${block}CODEX_LOG`);

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
  const cipherEvent = events.find((event) => event.event === "Cipher.doFinal");
  assert.equal(requestEvent.direction, "outbound");
  assert.equal(responseEvent.direction, "inbound");
  assert.equal(JSON.parse(requestEvent.payloads[0].text).msg, "请求中文显文");
  assert.equal(JSON.parse(requestEvent.payloads[0].text).note, "发送体验");
  assert.equal(JSON.parse(responseEvent.payloads[0].text).msg, "回包中文显文");
  assert.equal(JSON.parse(responseEvent.payloads[0].text).商品, "测试商品");
  assert.equal(requestEvent.payloads[0].encoding, "json / UTF-8");
  assert.equal(responseEvent.payloads[0].encoding, "json / UTF-8");
  assert.equal(cipherEvent.payloads[0].binary, true);
  assert.equal(cipherEvent.payloads[0].encoding, "binary/ciphertext");
  assert.equal(cipherEvent.payloads[0].text, "");
  console.log("MCP 真机 UTF-8 与密文字节读取校验通过");
} finally {
  await client.close().catch(() => {});
  await root(`rm -rf '/sdcard/Android/data/${packageName}/files/dandelion-hot-dumps'`);
}
