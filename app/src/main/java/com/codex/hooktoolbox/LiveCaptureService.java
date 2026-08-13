package com.codex.hooktoolbox;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.view.Gravity;
import android.view.WindowManager;
import android.widget.TextView;

import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class LiveCaptureService extends Service {
    interface Listener {
        void onLiveEvent(JSONObject event);
        void onLiveState(boolean running, String packageName, String error);
    }

    private static final String CHANNEL_ID = "codex-live-capture";
    private static final int NOTIFICATION_ID = 7106;
    private static final String[] SOURCES = {
            "java-crypto.log", "conscrypt-crypto.log", "boringssl-crypto.log", "http-network.log"
    };
    private static final Set<Listener> LISTENERS = new CopyOnWriteArraySet<>();
    private static final Deque<JSONObject> EVENTS = new ArrayDeque<>();
    private static final Deque<JSONObject> METADATA_EVENTS = new ArrayDeque<>();
    private static final int MAX_EVENTS = 80;
    private static final int MAX_METADATA_EVENTS = 20;
    private static final int MAX_LINE_CHARS = 256 * 1024;
    private static final int MAX_BLOCK_CHARS = 272 * 1024;
    private static volatile boolean active;
    private static volatile String activePackage = "";
    private final ExecutorService workers = Executors.newCachedThreadPool();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final List<Process> processes = new ArrayList<>();
    private final Set<Integer> rootTailPids = new HashSet<>();
    private final Object processLock = new Object();
    private WindowManager windowManager;
    private TextView floatingView;
    private volatile String packageName = "";
    private volatile boolean running;

    static void start(Context context, String pkg, boolean floating) {
        Intent intent = new Intent(context, LiveCaptureService.class)
                .putExtra("packageName", pkg).putExtra("floating", floating);
        if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent);
        else context.startService(intent);
    }

    static void stop(Context context) {
        context.stopService(new Intent(context, LiveCaptureService.class));
    }

    static void setFloating(Context context, String pkg, boolean enabled) {
        if (!enabled && !active) return;
        start(context, pkg, enabled);
    }

    static void addListener(Listener listener) { LISTENERS.add(listener); }
    static void removeListener(Listener listener) { LISTENERS.remove(listener); }

    @Override public void onCreate() {
        super.onCreate();
        createChannel();
        startForeground(NOTIFICATION_ID, notification("等待目标日志"));
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        String requested = intent == null ? "" : intent.getStringExtra("packageName");
        boolean floating = intent != null && intent.getBooleanExtra("floating", false);
        if (requested == null || requested.trim().isEmpty()) {
            stopReaders("未选择目标应用");
            return START_NOT_STICKY;
        }
        try {
            String normalized = Target.requirePackage(requested);
            if (!normalized.equals(packageName) || !running) startReaders(normalized);
            if (floating) showFloating(); else hideFloating();
        } catch (RuntimeException e) {
            state(false, requested, e.getMessage());
        }
        return START_NOT_STICKY;
    }

    @Override public void onDestroy() {
        stopReaders("服务停止");
        hideFloating();
        workers.shutdownNow();
        super.onDestroy();
    }

    @Override public IBinder onBind(Intent intent) { return null; }

    static JSONObject snapshot() throws org.json.JSONException {
        JSONObject result = new JSONObject();
        result.put("ok", true);
        result.put("running", active);
        result.put("packageName", activePackage);
        return result;
    }

    static JSONObject events(String requestedSource, int requestedLimit, boolean includeMetadata)
            throws org.json.JSONException {
        String source = normalizeSource(requestedSource);
        int limit = Math.max(1, Math.min(120, requestedLimit));
        List<JSONObject> snapshot = new ArrayList<>();
        int hidden;
        synchronized (EVENTS) {
            snapshot.addAll(EVENTS);
            hidden = METADATA_EVENTS.size();
            if (includeMetadata) snapshot.addAll(METADATA_EVENTS);
        }
        snapshot.sort((left, right) -> Long.compare(right.optLong("timeMs"), left.optLong("timeMs")));
        org.json.JSONArray array = new org.json.JSONArray();
        for (JSONObject event : snapshot) {
            if (array.length() >= limit) break;
            if (!"all".equals(source) && !source.equals(event.optString("source"))) continue;
            array.put(event);
        }
        JSONObject result = new JSONObject();
        result.put("ok", true);
        result.put("events", array);
        result.put("filtered", hidden);
        result.put("includeNoise", includeMetadata);
        result.put("source", source);
        return result;
    }

    private void startReaders(String pkg) {
        stopReaders("切换目标");
        packageName = pkg;
        running = true;
        active = true;
        activePackage = pkg;
        synchronized (EVENTS) { EVENTS.clear(); METADATA_EVENTS.clear(); }
        state(true, pkg, "");
        startForeground(NOTIFICATION_ID, notification("实时读取 " + pkg));
        for (String source : SOURCES) workers.execute(() -> readSource(pkg, source));
    }

    private void stopReaders(String reason) {
        running = false;
        active = false;
        synchronized (processLock) {
            if (!rootTailPids.isEmpty()) {
                StringBuilder command = new StringBuilder("kill");
                for (int pid : rootTailPids) command.append(' ').append(pid);
                RootShell.run(command.append(" 2>/dev/null || true").toString());
                rootTailPids.clear();
            }
            for (Process process : processes) process.destroy();
            processes.clear();
        }
        if (!packageName.isEmpty()) state(false, packageName, reason);
    }

    private void readSource(String pkg, String source) {
        String path = "/sdcard/Android/data/" + pkg + "/files/dandelion-hot-dumps/" + source;
        String quotedPath = RootShell.quote(path);
        int ownerPid = android.os.Process.myPid();
        String script = "size=$(stat -c %s " + quotedPath + " 2>/dev/null || echo 0); "
                + "echo $$; tail -c +$((size+1)) -F " + quotedPath + " & child=$!; "
                + "trap 'kill -9 $child 2>/dev/null' EXIT HUP INT TERM; "
                + "while [ -d /proc/" + ownerPid + " ] && kill -0 $child 2>/dev/null; do sleep 1; done; "
                + "kill -9 $child 2>/dev/null; exit 0";
        Process process = null;
        int rootPid = -1;
        try {
            process = new ProcessBuilder("su", "-c", script).redirectErrorStream(true).start();
            synchronized (processLock) { processes.add(process); }
            InputStreamReader reader = new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8);
            rootPid = readPidLine(reader);
            if (rootPid > 0) synchronized (processLock) { rootTailPids.add(rootPid); }
            StringBuilder block = new StringBuilder();
            StringBuilder line = new StringBuilder();
            boolean drop = false;
            boolean lineOverflow = false;
            char[] chars = new char[8192];
            int count;
            while (running && pkg.equals(packageName) && (count = reader.read(chars)) >= 0) {
                for (int i = 0; i < count; i++) {
                    char value = chars[i];
                    if (value != '\n') {
                        if (line.length() < MAX_LINE_CHARS) line.append(value);
                        else lineOverflow = true;
                        continue;
                    }
                    String current = line.toString();
                    line.setLength(0);
                    if (current.endsWith("\r")) current = current.substring(0, current.length() - 1);
                    if (current.startsWith("event=")) {
                        block.setLength(0);
                        String eventName = current.substring("event=".length()).trim().toLowerCase(java.util.Locale.ROOT);
                        drop = eventName.contains("digest") || eventName.contains("hmac") || eventName.startsWith("mac.");
                    }
                    if (!drop && block.length() < MAX_BLOCK_CHARS) {
                        int remaining = MAX_BLOCK_CHARS - block.length();
                        int accepted = Math.min(current.length(), Math.max(0, remaining - 1));
                        if (accepted > 0) block.append(current, 0, accepted);
                        block.append('\n');
                        if (lineOverflow && block.length() + 20 < MAX_BLOCK_CHARS) {
                            block.append("payload_truncated=1\n");
                        }
                    }
                    if ("---".equals(current)) {
                        if (!drop) emit(source, block.toString());
                        block.setLength(0);
                        drop = false;
                    }
                    lineOverflow = false;
                }
            }
        } catch (IOException e) {
            if (running && pkg.equals(packageName)) state(false, pkg, source + ": " + e.getMessage());
        } finally {
            if (process != null) {
                synchronized (processLock) {
                    processes.remove(process);
                    if (rootPid > 0) rootTailPids.remove(rootPid);
                }
                process.destroy();
            }
        }
    }

    private static int readPidLine(InputStreamReader reader) throws IOException {
        StringBuilder value = new StringBuilder();
        int character;
        while ((character = reader.read()) >= 0 && character != '\n' && value.length() < 16) {
            if (character != '\r') value.append((char) character);
        }
        try {
            return Integer.parseInt(value.toString().trim());
        } catch (NumberFormatException ignored) {
            throw new IOException("无法读取 root tail PID: " + value);
        }
    }

    private void emit(String source, String block) {
        try {
            JSONObject event = LogEventReader.parseLiveBlock(source, block);
            if (event == null) return;
            synchronized (EVENTS) {
                Deque<JSONObject> target = event.optBoolean("metadata") ? METADATA_EVENTS : EVENTS;
                int maximum = event.optBoolean("metadata") ? MAX_METADATA_EVENTS : MAX_EVENTS;
                target.addLast(event);
                while (target.size() > maximum) target.removeFirst();
            }
            for (Listener listener : LISTENERS) listener.onLiveEvent(event);
            updateFloating(event);
        } catch (Exception ignored) {
        }
    }

    private void state(boolean active, String pkg, String error) {
        for (Listener listener : LISTENERS) listener.onLiveState(active, pkg, error == null ? "" : error);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL_ID, "实时明文抓包", NotificationManager.IMPORTANCE_LOW));
    }

    private Notification notification(String text) {
        Intent launch = new Intent(this, MainActivity.class);
        PendingIntent pending = PendingIntent.getActivity(this, 0, launch,
                PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0));
        Notification.Builder builder = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(this, CHANNEL_ID) : new Notification.Builder(this);
        return builder.setSmallIcon(android.R.drawable.ic_menu_view).setContentTitle("Codex 实时抓包")
                .setContentText(text).setContentIntent(pending).setOngoing(true).build();
    }

    private void showFloating() {
        if (!Settings.canDrawOverlays(this)) {
            state(running, packageName, "未授予悬浮窗权限");
            return;
        }
        if (floatingView != null) return;
        windowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
        floatingView = new TextView(this);
        floatingView.setTextColor(Color.WHITE);
        floatingView.setTextSize(11);
        floatingView.setPadding(14, 10, 14, 10);
        floatingView.setText("实时抓包\n等待明文事件");
        GradientDrawable background = new GradientDrawable();
        background.setColor(0xee18211d);
        background.setCornerRadius(12);
        floatingView.setBackground(background);
        int type = Build.VERSION.SDK_INT >= 26 ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY : WindowManager.LayoutParams.TYPE_PHONE;
        WindowManager.LayoutParams params = new WindowManager.LayoutParams(300, 180, type,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.TRANSLUCENT);
        params.gravity = Gravity.TOP | Gravity.END;
        params.x = 12; params.y = 120;
        floatingView.setOnTouchListener(new FloatingTouchListener(windowManager, floatingView, params));
        windowManager.addView(floatingView, params);
    }

    private void hideFloating() {
        if (floatingView == null || windowManager == null) return;
        try { windowManager.removeView(floatingView); } catch (RuntimeException ignored) {}
        floatingView = null;
    }

    private void updateFloating(JSONObject event) {
        if (floatingView == null) return;
        if (event.optBoolean("metadata") || event.optBoolean("noise")) return;
        JSONObject fields = event.optJSONObject("fields");
        String source = event.optString("source", "");
        String direction = event.optString("direction", "unknown");
        String title = event.optString("event", source) + " / " + direction;
        String body = "";
        if (fields != null) body = fields.optString("url",
                fields.optString("response_body", fields.optString("request_body", "")));
        org.json.JSONArray payloads = event.optJSONArray("payloads");
        if (body.isEmpty() && payloads != null) {
            for (int i = 0; i < payloads.length(); i++) {
                JSONObject payload = payloads.optJSONObject(i);
                if (payload != null && !payload.optBoolean("binary") && !payload.optString("text").isEmpty()) {
                    body = payload.optString("text");
                    break;
                }
            }
        }
        if (body.isEmpty()) return;
        String text = title + "\n" + body;
        mainHandler.post(() -> { if (floatingView != null) floatingView.setText(text.length() > 900 ? text.substring(0, 900) : text); });
    }

    private static String normalizeSource(String source) {
        if ("java".equals(source)) return "java-crypto.log";
        if ("conscrypt".equals(source)) return "conscrypt-crypto.log";
        if ("boringssl".equals(source)) return "boringssl-crypto.log";
        if ("http".equals(source)) return "http-network.log";
        return "all";
    }

    private static final class FloatingTouchListener implements android.view.View.OnTouchListener {
        private final WindowManager manager; private final TextView view; private final WindowManager.LayoutParams params;
        private float downX, downY; private int startX, startY;
        FloatingTouchListener(WindowManager manager, TextView view, WindowManager.LayoutParams params) { this.manager = manager; this.view = view; this.params = params; }
        @Override public boolean onTouch(android.view.View v, android.view.MotionEvent event) {
            if (event.getAction() == android.view.MotionEvent.ACTION_DOWN) { downX = event.getRawX(); downY = event.getRawY(); startX = params.x; startY = params.y; return true; }
            if (event.getAction() == android.view.MotionEvent.ACTION_MOVE) { params.x = startX - (int)(event.getRawX() - downX); params.y = startY + (int)(event.getRawY() - downY); manager.updateViewLayout(view, params); return true; }
            return true;
        }
    }
}
