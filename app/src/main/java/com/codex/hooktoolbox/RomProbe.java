package com.codex.hooktoolbox;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.Map;

/** 只读取当前运行 ROM 已声明的 Hook 接口。 */
final class RomProbe {
    private static final String TRACE_NODE = "/proc/pine_syscall_trace";
    private static final String ART_LIBRARY = "/apex/com.android.art/lib64/libart.so";
    private static final String CRYPTO_LIBRARY = "/apex/com.android.conscrypt/lib64/libcrypto.so";
    private static final String WATCHDOG_MODULE = "/data/adb/.vndmods/imaotai_bangcle_watchdog_patch";

    JSONObject probe(String packageName) throws JSONException {
        String pkg = Target.requirePackage(packageName);
        String q = RootShell.quote(pkg);
        String files = "/sdcard/Android/data/" + pkg + "/files";
        String logs = files + "/dandelion-hot-dumps";
        String art = "/data/temp/pine-art-dumps/" + pkg;
        String script = "pkg=" + q + "\n"
                + "kv(){ printf '%s=%s\\n' \"$1\" \"$2\"; }\n"
                + "kv root_uid \"$(id -u 2>/dev/null)\"\n"
                + "uid=$(cmd package list packages -U \"$pkg\" 2>/dev/null | sed -n 's/.* uid:\\([0-9][0-9]*\\).*/\\1/p' | head -n1)\n"
                + "kv installed \"$([ -n \"$uid\" ] && echo 1 || echo 0)\"\n"
                + "kv uid \"$uid\"\n"
                + "pc=$(ps -A -o NAME 2>/dev/null | awk -v p=\"$pkg\" '$1==p || index($1,p \":\")==1 {n++} END{print n+0}'); kv process_count \"$pc\"\n"
                + "kv trace_exists \"$([ -e " + TRACE_NODE + " ] && echo 1 || echo 0)\"\n"
                + "kv trace_readable \"$([ -r " + TRACE_NODE + " ] && echo 1 || echo 0)\"\n"
                + "kv trace_writable \"$([ -w " + TRACE_NODE + " ] && echo 1 || echo 0)\"\n"
                + "kv trace_state \"$(cat " + TRACE_NODE + " 2>/dev/null | tr '\\n' ';')\"\n"
                + "kv art_library \"$([ -f " + ART_LIBRARY + " ] && echo 1 || echo 0)\"\n"
                + "kv art_debug \"$(getprop debug.pine.art_dexdump)\"\n"
                + "kv art_debug_pkg \"$(getprop debug.pine.art_dexdump_pkg)\"\n"
                + "kv art_persist \"$(getprop persist.sys.pine_art_dexdump)\"\n"
                + "kv art_persist_pkg \"$(getprop persist.sys.pine_art_dexdump_pkg)\"\n"
                + "kv art_marker \"$([ -f /data/temp/pine-art-dump.enable ] && echo 1 || echo 0)\"\n"
                + "kv art_marker_pkg \"$(cat /data/temp/pine-art-dump.pkg 2>/dev/null | head -n1)\"\n"
                + "kv art_files \"$(find " + RootShell.quote(art) + " -maxdepth 1 -type f 2>/dev/null | wc -l)\"\n"
                + "kv art_bytes \"$(du -sk " + RootShell.quote(art) + " 2>/dev/null | awk '{print $1*1024}')\"\n"
                + "kv crypto_library \"$([ -f " + CRYPTO_LIBRARY + " ] && echo 1 || echo 0)\"\n"
                + "kv hot_marker \"$([ -f " + RootShell.quote(files + "/dandelion-hot.enable") + " ] && echo 1 || echo 0)\"\n"
                + "kv hot_marker_value \"$(cat " + RootShell.quote(files + "/dandelion-hot.enable") + " 2>/dev/null | head -n1)\"\n"
                + statLine("java", logs + "/java-crypto.log")
                + statLine("conscrypt", logs + "/conscrypt-crypto.log")
                + statLine("boringssl", logs + "/boringssl-crypto.log")
                + statLine("http", logs + "/http-network.log")
                + "kv watchdog_module \"$([ -d " + WATCHDOG_MODULE + " ] && echo 1 || echo 0)\"\n";
        RootShell.Result result = RootShell.run(script);
        Map<String, String> values = parse(result.output);
        JSONObject json = new JSONObject();
        json.put("ok", result.ok && "0".equals(values.get("root_uid")));
        json.put("packageName", pkg);
        for (Map.Entry<String, String> entry : values.entrySet()) {
            putTyped(json, entry.getKey(), entry.getValue());
        }
        if (!result.ok) json.put("error", result.output.trim());
        return json;
    }

    private static String statLine(String key, String path) {
        String q = RootShell.quote(path);
        return "kv log_" + key + "_exists \"$([ -f " + q + " ] && echo 1 || echo 0)\"\n"
                + "kv log_" + key + "_bytes \"$(stat -c %s " + q + " 2>/dev/null || echo 0)\"\n";
    }

    private static Map<String, String> parse(String output) {
        Map<String, String> values = new LinkedHashMap<>();
        for (String line : output.split("\\n")) {
            int split = line.indexOf('=');
            if (split > 0) values.put(line.substring(0, split), line.substring(split + 1));
        }
        return values;
    }

    private static void putTyped(JSONObject json, String key, String value) throws JSONException {
        if (key.endsWith("_bytes") || key.endsWith("_files") || key.equals("uid") || key.equals("process_count")) {
            try {
                json.put(key, Long.parseLong(value.trim()));
                return;
            } catch (NumberFormatException ignored) {
            }
        }
        if (key.equals("installed") || key.endsWith("_exists") || key.endsWith("_readable")
                || key.endsWith("_writable") || key.endsWith("_library") || key.endsWith("_marker")
                || key.equals("watchdog_module")) {
            json.put(key, "1".equals(value));
            return;
        }
        json.put(key, value);
    }
}
