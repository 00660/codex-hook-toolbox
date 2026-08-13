package com.codex.hooktoolbox;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.net.Uri;
import android.os.Environment;
import android.provider.MediaStore;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

final class ExportManager {
    private static final long MAX_RAW_LOG_BYTES = 16L * 1024 * 1024;
    private final Context context;
    private final LogEventReader logReader;

    ExportManager(Context context, LogEventReader logReader) {
        this.context = context.getApplicationContext();
        this.logReader = logReader;
    }

    JSONObject export(String packageName, String type) throws Exception {
        String pkg = Target.requirePackage(packageName);
        if (!type.equals("logs") && !type.equals("dex") && !type.equals("so")) {
            throw new IllegalArgumentException("导出类型无效");
        }
        File root = new File(context.getExternalFilesDir(null), "exports");
        File stage = new File(root, "stage-" + System.nanoTime());
        if (!stage.mkdirs()) throw new IOException("无法创建导出暂存目录");
        try {
            Stats stats;
            if ("logs".equals(type)) stats = stageLogs(pkg, stage);
            else if ("dex".equals(type)) stats = stageDex(pkg, stage);
            else stats = stageSo(pkg, stage);
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(new Date());
            String name = pkg + "-" + type + "-" + stamp + ".zip";
            File archive = new File(root, name);
            zip(stage, archive);
            String uri = publish(archive, name);
            JSONObject result = new JSONObject();
            result.put("ok", true);
            result.put("name", name);
            result.put("uri", uri);
            result.put("files", stats.files);
            result.put("bytes", archive.length());
            result.put("sha256", sha256(archive));
            return result;
        } finally {
            deleteRecursively(stage);
        }
    }

    private Stats stageLogs(String pkg, File stage) throws Exception {
        File raw = new File(stage, "raw");
        File derived = new File(stage, "derived");
        raw.mkdirs();
        derived.mkdirs();
        String source = "/sdcard/Android/data/" + pkg + "/files/dandelion-hot-dumps";
        String command = "for n in java-crypto.log conscrypt-crypto.log boringssl-crypto.log http-network.log; do "
                + "f=" + RootShell.quote(source) + "/$n; [ -f \"$f\" ] || continue; "
                + "tail -c " + MAX_RAW_LOG_BYTES + " \"$f\" > "
                + RootShell.quote(raw.getAbsolutePath()) + "/$n; done; "
                + "find " + RootShell.quote(stage.getAbsolutePath()) + " -type d -exec chmod 0777 {} +; "
                + "find " + RootShell.quote(stage.getAbsolutePath()) + " -type f -exec chmod 0666 {} +";
        RootShell.Result copied = RootShell.run(command, 40);
        if (!copied.ok) throw new IOException("原始日志复制失败: " + copied.output.trim());
        JSONObject decoded = logReader.read(pkg, "all", 120, true);
        write(new File(derived, "events.json"), decoded.toString(2));
        write(new File(stage, "manifest.txt"),
                "package=" + pkg + "\nkind=logs\nraw_tail_limit_per_file=" + MAX_RAW_LOG_BYTES
                        + "\nderived=derived/events.json\nraw_preserved=true\n");
        return new Stats(countFiles(stage));
    }

    private Stats stageDex(String pkg, File stage) throws Exception {
        File raw = new File(stage, "dex");
        raw.mkdirs();
        String source = "/data/temp/pine-art-dumps/" + pkg;
        String command = "for f in " + RootShell.quote(source) + "/*.dex "
                + RootShell.quote(source) + "/*.cdex; do [ -f \"$f\" ] || continue; "
                + "h=$(sha256sum \"$f\" | awk '{print $1}'); case \"$f\" in *.cdex) e=cdex;; *) e=dex;; esac; "
                + "o=" + RootShell.quote(raw.getAbsolutePath()) + "/$h.$e; [ -f \"$o\" ] || cp -f \"$f\" \"$o\"; "
                + "m=\"$f.meta\"; [ ! -f \"$m\" ] || cp -f \"$m\" "
                + RootShell.quote(raw.getAbsolutePath()) + "/$h.$e.meta; done; "
                + "find " + RootShell.quote(stage.getAbsolutePath()) + " -type d -exec chmod 0777 {} +; "
                + "find " + RootShell.quote(stage.getAbsolutePath()) + " -type f -exec chmod 0666 {} +";
        RootShell.Result copied = RootShell.run(command, 60);
        if (!copied.ok) throw new IOException("DEX 导出失败: " + copied.output.trim());
        write(new File(stage, "manifest.txt"),
                "package=" + pkg + "\nkind=dex\ndedup=sha256\nsource=" + source + "\n");
        return new Stats(countFiles(stage));
    }

    private Stats stageSo(String pkg, File stage) throws Exception {
        File mapsDir = new File(stage, "maps");
        File diskDir = new File(stage, "disk");
        File memoryDir = new File(stage, "memory");
        mapsDir.mkdirs();
        diskDir.mkdirs();
        memoryDir.mkdirs();
        RootShell.Result pids = RootShell.run("for p in /proc/[0-9]*; do "
                + "n=$(tr '\\0' '\\n' <\"$p/cmdline\" 2>/dev/null | head -n1); "
                + "case \"$n\" in " + pkg + "|" + pkg + ":*) basename \"$p\";; esac; done");
        if (!pids.ok) throw new IOException("无法读取目标进程");
        int processCount = 0;
        Set<String> copiedPaths = new HashSet<>();
        for (String line : pids.output.split("\\n")) {
            if (!line.matches("[0-9]+")) continue;
            int pid = Integer.parseInt(line);
            RootShell.Result mapsResult = RootShell.run("cat /proc/" + pid + "/maps");
            if (!mapsResult.ok) continue;
            processCount++;
            write(new File(mapsDir, "pid-" + pid + ".maps"), mapsResult.output);
            List<MapEntry> entries = MapEntry.parseAll(mapsResult.output);
            int memoryCount = 0;
            for (MapEntry entry : entries) {
                if (!entry.path.endsWith(".so") || !entry.readable || entry.length() <= 0) continue;
                if (entry.path.contains(pkg) && copiedPaths.add(entry.path)) {
                    String name = sha256(entry.path.getBytes(StandardCharsets.UTF_8)).substring(0, 16)
                            + "-" + new File(entry.path).getName();
                    RootShell.run("cp -f " + RootShell.quote(entry.path) + " "
                            + RootShell.quote(new File(diskDir, name).getAbsolutePath()) + " 2>/dev/null || true");
                }
                boolean targetMapping = entry.path.contains(pkg)
                        || entry.path.contains("/data/data/" + pkg)
                        || entry.path.contains("/data/user/0/" + pkg)
                        || entry.path.contains("(deleted)")
                        || entry.path.contains("memfd");
                if (targetMapping && entry.offset == 0 && entry.executable
                        && entry.length() <= 64L * 1024 * 1024
                        && memoryCount < 16) {
                    String memory = new File(memoryDir,
                            "pid-" + pid + "-" + Long.toHexString(entry.start) + ".so").getAbsolutePath();
                    String command = "m=$(dd if=/proc/" + pid + "/mem bs=4 skip=" + entry.start
                            + " count=1 iflag=skip_bytes status=none 2>/dev/null | od -An -tx1 | tr -d ' \\n'); "
                            + "[ \"$m\" = 7f454c46 ] && dd if=/proc/" + pid + "/mem of="
                            + RootShell.quote(memory) + " bs=4096 skip=" + entry.start + " count="
                            + entry.length() + " iflag=skip_bytes,count_bytes status=none 2>/dev/null || true";
                    RootShell.run(command, 30);
                    memoryCount++;
                }
            }
        }
        makeStageReadable(stage);
        write(new File(stage, "manifest.txt"),
                "package=" + pkg + "\nkind=so\nprocesses=" + processCount
                        + "\ndisk=disk/\nmemory=memory/\nmaps=maps/\n");
        return new Stats(countFiles(stage));
    }

    private String publish(File archive, String name) throws IOException {
        ContentResolver resolver = context.getContentResolver();
        ContentValues values = new ContentValues();
        values.put(MediaStore.Downloads.DISPLAY_NAME, name);
        values.put(MediaStore.Downloads.MIME_TYPE, "application/zip");
        values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/CodexHookToolbox");
        values.put(MediaStore.Downloads.IS_PENDING, 1);
        Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
        if (uri == null) throw new IOException("无法创建下载文件");
        try (OutputStream output = resolver.openOutputStream(uri);
             BufferedInputStream input = new BufferedInputStream(new FileInputStream(archive))) {
            if (output == null) throw new IOException("无法打开下载文件");
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) >= 0) output.write(buffer, 0, count);
        } catch (IOException e) {
            resolver.delete(uri, null, null);
            throw e;
        }
        ContentValues ready = new ContentValues();
        ready.put(MediaStore.Downloads.IS_PENDING, 0);
        resolver.update(uri, ready, null, null);
        archive.delete();
        return uri.toString();
    }

    private static void zip(File source, File destination) throws IOException {
        List<File> files = new ArrayList<>();
        collect(source, files);
        try (ZipOutputStream zip = new ZipOutputStream(
                new BufferedOutputStream(new FileOutputStream(destination)))) {
            zip.setLevel(1);
            for (File file : files) {
                String relative = source.toPath().relativize(file.toPath()).toString().replace(File.separatorChar, '/');
                zip.putNextEntry(new ZipEntry(relative));
                try (BufferedInputStream input = new BufferedInputStream(new FileInputStream(file))) {
                    byte[] buffer = new byte[64 * 1024];
                    int count;
                    while ((count = input.read(buffer)) >= 0) zip.write(buffer, 0, count);
                }
                zip.closeEntry();
            }
        }
    }

    private static void collect(File root, List<File> files) {
        File[] children = root.listFiles();
        if (children == null) return;
        for (File child : children) {
            if (child.isDirectory()) collect(child, files);
            else files.add(child);
        }
    }

    private static int countFiles(File root) {
        List<File> files = new ArrayList<>();
        collect(root, files);
        return files.size();
    }

    private static void write(File file, String value) throws IOException {
        try (FileOutputStream output = new FileOutputStream(file)) {
            output.write(value.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static void makeStageReadable(File stage) {
        String root = RootShell.quote(stage.getAbsolutePath());
        RootShell.run("find " + root + " -type d -exec chmod 0777 {} +; "
                + "find " + root + " -type f -exec chmod 0666 {} +");
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (FileInputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) >= 0) digest.update(buffer, 0, count);
        }
        return hex(digest.digest());
    }

    private static String sha256(byte[] value) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) result.append(String.format(Locale.US, "%02x", value));
        return result.toString();
    }

    private static void deleteRecursively(File file) {
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) for (File child : children) deleteRecursively(child);
        }
        file.delete();
    }

    private static final class Stats {
        final int files;
        Stats(int files) { this.files = files; }
    }

    private static final class MapEntry {
        final long start;
        final long end;
        final long offset;
        final String path;
        final boolean readable;
        final boolean executable;

        MapEntry(long start, long end, long offset, String path, String perms) {
            this.start = start;
            this.end = end;
            this.offset = offset;
            this.path = path;
            this.readable = perms.startsWith("r");
            this.executable = perms.contains("x");
        }

        long length() { return end - start; }

        static List<MapEntry> parseAll(String maps) {
            List<MapEntry> result = new ArrayList<>();
            for (String line : maps.split("\\n")) {
                String[] fields = line.trim().split("\\s+", 6);
                if (fields.length < 5) continue;
                String[] range = fields[0].split("-", 2);
                if (range.length != 2) continue;
                try {
                    long start = Long.parseUnsignedLong(range[0], 16);
                    long end = Long.parseUnsignedLong(range[1], 16);
                    long offset = Long.parseUnsignedLong(fields[2], 16);
                    String path = fields.length == 6 ? fields[5] : "";
                    result.add(new MapEntry(start, end, offset, path, fields[1]));
                } catch (NumberFormatException ignored) {
                }
            }
            return result;
        }
    }
}
