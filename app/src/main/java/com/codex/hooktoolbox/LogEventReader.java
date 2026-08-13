package com.codex.hooktoolbox;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class LogEventReader {
    private static final long INITIAL_BYTES = 128 * 1024;
    private static final long MAX_DELTA_BYTES = 256 * 1024;
    private static final int MAX_EVENTS = 320;
    private static final Pattern EVENT_START = Pattern.compile("(?m)^event=");
    private static final List<String> SOURCES = Arrays.asList(
            "java-crypto.log", "conscrypt-crypto.log", "boringssl-crypto.log", "http-network.log");
    private final Map<String, Long> offsets = new HashMap<>();
    private final Map<String, String> pendingBlocks = new HashMap<>();
    private final Map<String, Deque<Event>> events = new HashMap<>();
    synchronized JSONObject read(String packageName, String requestedSource, int requestedLimit,
                                 boolean includeNoise)
            throws JSONException {
        String pkg = Target.requirePackage(packageName);
        int limit = Math.max(1, Math.min(120, requestedLimit));
        String sourceFilter = normalizeSource(requestedSource);
        String root = "/sdcard/Android/data/" + pkg + "/files/dandelion-hot-dumps/";
        Deque<Event> targetEvents = events.computeIfAbsent(pkg, ignored -> new ArrayDeque<>());
        for (String source : SOURCES) {
            if (!"all".equals(sourceFilter) && !source.equals(sourceFilter)) continue;
            readSource(root + source, source, targetEvents);
        }
        JSONArray array = new JSONArray();
        List<Event> snapshot = new ArrayList<>(targetEvents);
        snapshot.sort((left, right) -> Long.compare(right.timeMs(), left.timeMs()));
        int accepted = 0;
        int hidden = 0;
        for (Event event : snapshot) {
            if (accepted >= limit) break;
            if (!"all".equals(sourceFilter) && !event.source.equals(sourceFilter)) continue;
            if (event.metadata || (event.noise && !includeNoise)) {
                hidden++;
                continue;
            }
            array.put(event.toJson());
            accepted++;
        }
        JSONObject result = new JSONObject();
        result.put("ok", true);
        result.put("events", array);
        result.put("filtered", hidden);
        result.put("includeNoise", includeNoise);
        result.put("source", sourceFilter);
        return result;
    }

    private void readSource(String path, String source, Deque<Event> target) {
        RootShell.Result sizeResult = RootShell.run("stat -c %s " + RootShell.quote(path) + " 2>/dev/null || echo 0");
        long size = parseLong(sizeResult.output);
        String key = path;
        Long oldValue = offsets.get(key);
        long old = oldValue == null ? Math.max(0, size - INITIAL_BYTES) : oldValue;
        if (size < old) {
            old = 0;
            pendingBlocks.remove(key);
        }
        long delta = size - old;
        offsets.put(key, size);
        if (delta <= 0) {
            flushPending(key, source, target);
            return;
        }
        long read = Math.min(delta, MAX_DELTA_BYTES);
        if (delta > MAX_DELTA_BYTES) pendingBlocks.remove(key);
        RootShell.Result content = RootShell.run("tail -c " + read + " " + RootShell.quote(path), 20);
        if (!content.ok || content.output.isEmpty()) return;
        parseStreaming(key, content.output, source, target);
        while (target.size() > MAX_EVENTS) target.removeFirst();
    }

    private void parseStreaming(String key, String delta, String source, Deque<Event> target) {
        String text = pendingBlocks.getOrDefault(key, "") + delta;
        Matcher matcher = EVENT_START.matcher(text);
        List<Integer> starts = new ArrayList<>();
        while (matcher.find()) starts.add(matcher.start());
        if (starts.isEmpty()) {
            pendingBlocks.remove(key);
            return;
        }
        for (int i = 0; i + 1 < starts.size(); i++) {
            addEvent(text.substring(starts.get(i), starts.get(i + 1)), source, target);
        }
        pendingBlocks.put(key, text.substring(starts.get(starts.size() - 1)));
    }

    private void flushPending(String key, String source, Deque<Event> target) {
        String block = pendingBlocks.remove(key);
        if (block != null) addEvent(block, source, target);
    }

    private void addEvent(String block, String source, Deque<Event> target) {
        LinkedHashMap<String, String> eventFields = fields(block);
        String name = eventFields.getOrDefault("event", "");
        if (name.isEmpty()) return;
        target.addLast(new Event(source, name, eventFields, block.trim(),
                isCryptoNoise(name), isMetadata(name)));
    }

    static String[] splitBlocks(String text) {
        return text.split("(?m)^---\\s*$|(?=^event=)");
    }

    static JSONObject parseLiveBlock(String source, String block) throws JSONException {
        LinkedHashMap<String, String> eventFields = fields(block);
        String name = eventFields.getOrDefault("event", "");
        if (name.isEmpty()) return null;
        JSONObject event = new Event(source, name, eventFields, block.trim(),
                isCryptoNoise(name), isMetadata(name)).toJson();
        event.remove("raw");
        return event;
    }

    private static LinkedHashMap<String, String> fields(String block) {
        LinkedHashMap<String, String> fields = new LinkedHashMap<>();
        for (String line : block.split("\\n")) {
            int split = line.indexOf('=');
            if (split > 0) fields.put(line.substring(0, split).trim(), line.substring(split + 1).trim());
        }
        return fields;
    }

    private static boolean isMetadata(String event) {
        String normalized = event.toLowerCase(java.util.Locale.ROOT);
        return normalized.startsWith("socket.send") || normalized.startsWith("socket.recv");
    }

    private static boolean isCryptoNoise(String event) {
        String normalized = event.toLowerCase(java.util.Locale.ROOT);
        return normalized.contains("digest") || normalized.startsWith("mac.") || normalized.contains("hmac");
    }

    private static String normalizeSource(String source) {
        if ("java".equals(source)) return "java-crypto.log";
        if ("conscrypt".equals(source)) return "conscrypt-crypto.log";
        if ("boringssl".equals(source)) return "boringssl-crypto.log";
        if ("http".equals(source)) return "http-network.log";
        return "all";
    }

    private static long parseLong(String value) {
        try {
            String first = value.trim().split("\\s+")[0];
            return Long.parseLong(first);
        } catch (Exception ignored) {
            return 0;
        }
    }

    static final class Event {
        final String source;
        final String name;
        final LinkedHashMap<String, String> fields;
        final String raw;
        final boolean noise;
        final boolean metadata;

        Event(String source, String name, LinkedHashMap<String, String> fields, String raw,
              boolean noise, boolean metadata) {
            this.source = source;
            this.name = name;
            this.fields = fields;
            this.raw = raw;
            this.noise = noise;
            this.metadata = metadata;
        }

        JSONObject toJson() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("source", source);
            json.put("event", name);
            json.put("timeMs", timeMs());
            json.put("direction", direction(fields, name));
            json.put("raw", raw);
            json.put("noise", noise);
            json.put("metadata", metadata);
            JSONObject allFields = new JSONObject();
            JSONArray payloads = new JSONArray();
            String hints = String.join(" ", fields.values());
            for (Map.Entry<String, String> entry : fields.entrySet()) {
                if (!entry.getKey().endsWith("_hex")) allFields.put(entry.getKey(), entry.getValue());
                if (entry.getKey().endsWith("_hex") && entry.getValue().matches("(?i)[0-9a-f\\s]+")) {
                    PayloadDecoder.Decoded decoded = PayloadDecoder.decodeHex(entry.getValue(), hints);
                    JSONObject payload = new JSONObject();
                    payload.put("field", entry.getKey());
                    payload.put("rawHex", decoded.rawHex);
                    payload.put("text", decoded.text);
                    payload.put("encoding", decoded.encoding);
                    payload.put("binary", decoded.binary);
                    payload.put("truncated", decoded.truncated);
                    payloads.put(payload);
                } else if (isTextPayload(entry.getKey()) && !entry.getValue().isEmpty()) {
                    JSONObject payload = new JSONObject();
                    payload.put("field", entry.getKey());
                    payload.put("rawHex", "");
                    payload.put("text", entry.getValue());
                    payload.put("encoding", "UTF-8");
                    payload.put("binary", false);
                    payload.put("truncated", false);
                    payloads.put(payload);
                }
            }
            json.put("fields", allFields);
            json.put("payloads", payloads);
            return json;
        }

        private static boolean isTextPayload(String key) {
            return "request_body".equals(key) || "response_body".equals(key) || "body".equals(key)
                    || "plain".equals(key) || "request_headers".equals(key) || "response_headers".equals(key)
                    || "headers".equals(key) || "header".equals(key);
        }

        long timeMs() {
            return numericTime(fields);
        }

        private static long numericTime(Map<String, String> fields) {
            String value = fields.getOrDefault("time_ms", fields.getOrDefault("timestamp_ns", "0"));
            try {
                long parsed = Long.parseLong(value.replaceAll("[^0-9]", ""));
                return fields.containsKey("time_ms") ? parsed : parsed / 1_000_000L;
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }

        private static String direction(Map<String, String> fields, String event) {
            String declared = fields.getOrDefault("direction", "");
            if (!declared.isEmpty()) return declared;
            String upper = (fields.getOrDefault("op", "") + " " + fields.getOrDefault("opmode", "")).toUpperCase();
            if (upper.contains("ENCRYPT") || upper.contains("WRITE")) return "outbound";
            if (upper.contains("DECRYPT") || upper.contains("READ")) return "inbound";
            if (event.toLowerCase().contains("write") || event.toLowerCase().contains("request")) return "outbound";
            if (event.toLowerCase().contains("read") || event.toLowerCase().contains("response")) return "inbound";
            return "unknown";
        }
    }
}
