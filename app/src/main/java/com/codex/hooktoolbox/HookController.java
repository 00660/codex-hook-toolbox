package com.codex.hooktoolbox;

import org.json.JSONException;
import org.json.JSONObject;

final class HookController {
    private final RomProbe probe = new RomProbe();

    JSONObject setHot(String packageName, boolean enabled) throws JSONException {
        String pkg = Target.requirePackage(packageName);
        String files = "/sdcard/Android/data/" + pkg + "/files";
        String marker = files + "/dandelion-hot.enable";
        String stopped = files + "/dandelion-hot.stopped";
        String script;
        if (enabled) {
            script = "pkg=" + RootShell.quote(pkg) + "\n"
                    + "uid=$(cmd package list packages -U \"$pkg\" 2>/dev/null | sed -n 's/.* uid:\\([0-9][0-9]*\\).*/\\1/p' | head -n1); [ -n \"$uid\" ] || exit 2\n"
                    + "find /sdcard/Android/data -path '*/files/dandelion-hot.enable' -type f 2>/dev/null | while IFS= read -r old; do rm -f \"$old\"; done\n"
                    + "mkdir -p " + RootShell.quote(files + "/dandelion-hot-dumps") + "\n"
                    + "printf 'package=%s\\n' \"$pkg\" > " + RootShell.quote(marker) + "\n"
                    + "rm -f " + RootShell.quote(stopped) + "\n"
                    + "chmod 0777 " + RootShell.quote(files + "/dandelion-hot-dumps") + "; chmod 0666 " + RootShell.quote(marker) + "\n";
        } else {
            script = "rm -f " + RootShell.quote(marker) + "\n"
                    + "date +%s > " + RootShell.quote(stopped) + "\nchmod 0666 " + RootShell.quote(stopped) + "\n";
        }
        return actionResult("hot", enabled, RootShell.run(script), probe.probe(pkg));
    }

    JSONObject setArt(String packageName, boolean enabled) throws JSONException {
        String pkg = Target.requirePackage(packageName);
        String script;
        if (enabled) {
            script = "pkg=" + RootShell.quote(pkg) + "\n"
                    + "uid=$(cmd package list packages -U \"$pkg\" 2>/dev/null | sed -n 's/.* uid:\\([0-9][0-9]*\\).*/\\1/p' | head -n1); [ -n \"$uid\" ] || exit 2\n"
                    + "mkdir -p " + RootShell.quote("/data/temp/pine-art-dumps/" + pkg) + "\n"
                    + "chmod 0777 /data/temp/pine-art-dumps " + RootShell.quote("/data/temp/pine-art-dumps/" + pkg) + "\n"
                    + "setprop debug.pine.art_dexdump_pkg \"$pkg\"\nsetprop debug.pine.art_dexdump 1\n";
        } else {
            script = "setprop debug.pine.art_dexdump 0\nsetprop debug.pine.art_dexdump_pkg __disabled__\n"
                    + "setprop persist.sys.pine_art_dexdump false\n"
                    + "setprop persist.sys.pine_art_dexdump_pkg __disabled__\n"
                    + "rm -f /data/temp/pine-art-dump.enable /data/temp/pine-art-dump.pkg\n";
        }
        return actionResult("art", enabled, RootShell.run(script), probe.probe(pkg));
    }

    JSONObject launch(String packageName) throws JSONException {
        String pkg = Target.requirePackage(packageName);
        RootShell.Result result = RootShell.run("monkey -p " + RootShell.quote(pkg)
                + " -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1");
        return actionResult("launch", true, result, probe.probe(pkg));
    }

    JSONObject stopAll(String packageName) throws JSONException {
        String pkg = Target.requirePackage(packageName);
        String marker = "/sdcard/Android/data/" + pkg + "/files/dandelion-hot.enable";
        RootShell.Result result = RootShell.run("[ ! -w /proc/pine_syscall_trace ] || printf '0\\n' > /proc/pine_syscall_trace\n"
                + "rm -f " + RootShell.quote(marker) + " /data/temp/pine-art-dump.enable /data/temp/pine-art-dump.pkg\n"
                + "setprop debug.pine.art_dexdump 0\nsetprop debug.pine.art_dexdump_pkg __disabled__\n"
                + "setprop persist.sys.pine_art_dexdump false\n"
                + "setprop persist.sys.pine_art_dexdump_pkg __disabled__\n");
        return actionResult("all", false, result, probe.probe(pkg));
    }

    private static JSONObject actionResult(String action, boolean enabled, RootShell.Result result,
                                           JSONObject status) throws JSONException {
        JSONObject json = new JSONObject();
        json.put("ok", result.ok);
        json.put("action", action);
        json.put("requestedEnabled", enabled);
        json.put("status", status);
        if (!result.ok) json.put("error", result.output.trim());
        return json;
    }
}
