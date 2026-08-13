# Codex Hook 工具箱 APK

独立 Android 控制端，基于 ROM 已存在的 Pine ART、Crypto、HTTP 与 syscall trace 能力工作。

## 边界

- 不使用 Zygisk、Riru、LSPosed、JVMTI 或 Frida。
- 不向目标进程加载任何新 SO、DEX 或线程。
- 不替换 `libart`、`linker`、`libc`、Conscrypt、BoringSSL、APEX 或内核文件。
- 控制接口以目标设备 ROM 实时基线为准：ART 使用当前 APEX 声明的
  `debug.pine.art_dexdump*`，Crypto/HTTP 使用应用私有目录中的
  `dandelion-hot.*`，Trace 使用 `/proc/pine_syscall_trace`。
- 不写入当前 ROM 不存在的 `/data/temp/pine-crypto-dump.*`。
- 原始 Hex 始终保留，ASCII、UTF-8、GB18030、JSON、Gzip、Deflate 与 Brotli 结果属于派生视图。

旧 `com.codex.devicetools` 使用未知平台私钥和 `android.uid.system`，本工程使用独立包名 `com.codex.hooktoolbox`，通过设备现有 `su` 获取授权。

设备首次安装后，可通过 `device-grant-root.sh` 为工具箱当前 UID 写入既有
root 管理器策略。脚本先保留策略库备份，只修改工具箱 UID 对应的一行。
