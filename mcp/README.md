# Codex Hook 工具箱 MCP

`mcp/server.mjs` 是本项目的本地 STDIO MCP 服务，默认控制 `192.168.2.73:5555` 上已安装的 `com.codex.hooktoolbox`。默认只读；用户明确同意后，先调用 `authorize_controls` 并传 `confirmed=true`，当前 MCP 会话即可使用全部控制工具和 Android Shell。服务重启或新会话会恢复只读。

## 注册

```bash
codex mcp add codex_hook_toolbox -- node /workspace/codex-hook-toolbox/mcp/server.mjs
```

重启 Codex 或新开会话后，可用 `/mcp` 或 `codex mcp list` 确认已连接。其他设备通过启动 Codex 前设置 `CODEX_HOOK_DEVICE=IP:PORT` 覆盖默认地址。

## 工具

- `list_apps`、`probe`、`read_events`：读取应用、ROM 基线和实时明文事件。
- `set_hot`、`set_art`、`set_live_capture`、`launch_target`：控制工具箱的所有采集和启动能力。
- `trace_start`、`trace_stop`：控制受限 syscall Trace。
- `export_artifacts`：导出日志、DEX 或运行时 SO 证据包到设备 `下载/CodexHookToolbox`，并返回 SHA256。
- `stop_all`：停止实时读取、Hot、ART 和 Trace。
- `device_shell`：在已连接 Android 设备执行 Shell，可选 root 权限；只在当前 MCP 会话已完成授权后可用，绝不在宿主机执行。

MCP 只调用设备现有 ROM 节点和工具箱控制面，不向目标进程注入代码。
