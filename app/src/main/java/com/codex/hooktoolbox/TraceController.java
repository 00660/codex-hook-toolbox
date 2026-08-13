package com.codex.hooktoolbox;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class TraceController {
    private static final int MAX_RATE = 250;
    private static final int MAX_LINES = 5000;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private boolean running;
    private String packageName = "";
    private String scope = "";
    private int duration;
    private int elapsed;
    private int lines;
    private String stopReason = "未启动";
    private String traceText = "";

    synchronized JSONObject start(String requestedPackage, String requestedScope, int requestedDuration)
            throws JSONException {
        String pkg = Target.requirePackage(requestedPackage);
        if (running) return response(false, "已有 Trace 正在运行");
        String normalizedScope = "pid".equals(requestedScope) ? "pid" : "uid";
        int seconds = Math.max(3, Math.min(30, requestedDuration));
        RootShell.Result target = RootShell.run(targetCommand(pkg, normalizedScope));
        String id = target.output.trim();
        if (!target.ok || !id.matches("[0-9]+")) return response(false, "无法解析目标 " + normalizedScope);
        RootShell.Result baseline = RootShell.run(
                "[ -w /proc/pine_syscall_trace ] || exit 2\n"
                        + "dmesg | grep -c pine_syscall_trace || true\n"
                        + "printf '" + normalizedScope + " " + id + "\\n' > /proc/pine_syscall_trace\n"
                        + "cat /proc/pine_syscall_trace");
        if (!baseline.ok || !baseline.output.contains("enabled=1")) {
            RootShell.run("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true");
            return response(false, "Trace 节点未接受限定目标");
        }
        int baselineLines = firstInteger(baseline.output);
        running = true;
        packageName = pkg;
        scope = normalizedScope + " " + id;
        duration = seconds;
        elapsed = 0;
        lines = 0;
        stopReason = "运行中";
        traceText = "";
        worker.execute(() -> monitor(baselineLines));
        return response(true, "");
    }

    synchronized JSONObject stop() throws JSONException {
        RootShell.run("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true");
        if (running) stopReason = "手动停止";
        running = false;
        return response(true, "");
    }

    synchronized JSONObject state() throws JSONException {
        return response(true, "");
    }

    synchronized String latestTrace() {
        return traceText;
    }

    void shutdown() {
        RootShell.run("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true");
        synchronized (this) {
            running = false;
            stopReason = "控制端退出";
        }
        worker.shutdownNow();
    }

    private void monitor(int baselineLines) {
        int previous = 0;
        String reason = "达到时限";
        try {
            for (int second = 1; second <= duration; second++) {
                Thread.sleep(1000);
                synchronized (this) {
                    if (!running) return;
                }
                RootShell.Result countResult = RootShell.run(
                        "n=$(dmesg | grep pine_syscall_trace | wc -l); n=$((n-" + baselineLines
                                + ")); [ \"$n\" -lt 0 ] && n=0; printf '%s\\n' \"$n\"");
                int current = firstInteger(countResult.output);
                int rate = Math.max(0, current - previous);
                previous = current;
                synchronized (this) {
                    elapsed = second;
                    lines = current;
                }
                if (rate > MAX_RATE) {
                    reason = "速率熔断：" + rate + " 条/秒";
                    break;
                }
                if (current >= MAX_LINES) {
                    reason = "总量熔断：" + current + " 条";
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            reason = "任务中断";
        } finally {
            RootShell.run("printf '0\\n' > /proc/pine_syscall_trace 2>/dev/null || true");
            RootShell.Result capture = RootShell.run(
                    "dmesg | grep pine_syscall_trace | tail -n +" + (baselineLines + 1)
                            + " | head -n " + MAX_LINES, 20);
            synchronized (this) {
                traceText = capture.output;
                if (!running && !"运行中".equals(stopReason)) reason = stopReason;
                running = false;
                stopReason = reason;
            }
        }
    }

    private static String targetCommand(String pkg, String scope) {
        String q = RootShell.quote(pkg);
        if ("uid".equals(scope)) {
            return "cmd package list packages -U " + q
                    + " | sed -n 's/.* uid:\\([0-9][0-9]*\\).*/\\1/p' | head -n1";
        }
        return "for p in /proc/[0-9]*; do n=$(tr '\\0' '\\n' <\"$p/cmdline\" 2>/dev/null | head -n1); "
                + "[ \"$n\" = " + q + " ] && { basename \"$p\"; break; }; done";
    }

    private static int firstInteger(String text) {
        for (String line : text.split("\\n")) {
            String value = line.trim();
            if (value.matches("[0-9]+")) {
                try {
                    return Integer.parseInt(value);
                } catch (NumberFormatException ignored) {
                    return 0;
                }
            }
        }
        return 0;
    }

    private synchronized JSONObject response(boolean ok, String error) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("ok", ok);
        json.put("running", running);
        json.put("packageName", packageName);
        json.put("scope", scope);
        json.put("duration", duration);
        json.put("elapsed", elapsed);
        json.put("lines", lines);
        json.put("maxRate", MAX_RATE);
        json.put("maxLines", MAX_LINES);
        json.put("reason", stopReason);
        if (!error.isEmpty()) json.put("error", error);
        return json;
    }
}
