package com.codex.hooktoolbox;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** 最小 root 命令执行器，命令只能由固定类型的控制器组装。 */
final class RootShell {
    private static final long TIMEOUT_SECONDS = 12;
    private static final int MAX_OUTPUT = 6 * 1024 * 1024;
    private static final AtomicLong IDS = new AtomicLong();

    private RootShell() {}

    static Result run(String script) {
        return run(script, TIMEOUT_SECONDS);
    }

    static Result run(String script, long timeoutSeconds) {
        Process process = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            process = new ProcessBuilder("su", "-c", script)
                    .redirectErrorStream(true)
                    .start();
            Process running = process;
            Thread drain = new Thread(() -> {
                byte[] buffer = new byte[8192];
                try {
                    int count;
                    while ((count = running.getInputStream().read(buffer)) >= 0) {
                        if (output.size() < MAX_OUTPUT) {
                            output.write(buffer, 0, Math.min(count, MAX_OUTPUT - output.size()));
                        }
                    }
                } catch (IOException ignored) {
                }
            }, "root-output-drain-" + IDS.incrementAndGet());
            drain.start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                drain.join(1000);
                return new Result(false, new String(output.toByteArray(), StandardCharsets.UTF_8) + "\n命令超时");
            }
            drain.join(1000);
            return new Result(process.exitValue() == 0, new String(output.toByteArray(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            if (process != null) process.destroyForcibly();
            return new Result(false, "root 不可用: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            if (process != null) process.destroyForcibly();
            return new Result(false, "命令被中断");
        }
    }

    static String quote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    static String marker(String prefix) {
        return "__CODEX_" + prefix + "_" + IDS.incrementAndGet() + "__";
    }

    static final class Result {
        final boolean ok;
        final String output;

        Result(boolean ok, String output) {
            this.ok = ok;
            this.output = output == null ? "" : output;
        }
    }
}
