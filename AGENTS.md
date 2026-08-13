# Project Rules

- 所有用户界面与说明使用简体中文和 UTF-8 无 BOM。
- 禁止添加 Zygisk、Riru、LSPosed、JVMTI、Frida 或其他目标进程注入实现。
- 禁止替换设备 ROM、APEX、linker、libc、ART、Conscrypt、BoringSSL 或内核文件。
- Hook 状态必须来自 root 下的实际节点、marker、属性和日志，不得根据 UI 本地状态猜测。
- Trace 只能按目标 UID 或 TGID 开启，最长 30 秒，退出和异常时必须写 `0` 关闭。
- 原始证据与解码结果分开保存，解码结果不能覆盖原始 Hex。
