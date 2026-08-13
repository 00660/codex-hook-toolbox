package com.codex.hooktoolbox;

import org.brotli.dec.BrotliInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

final class PayloadDecoder {
    private static final int MAX_HEX_CHARS = 262_144;
    private static final int MAX_OUTPUT_BYTES = 512 * 1024;

    static Decoded decodeHex(String rawHex, String hints) {
        String normalized = rawHex == null ? "" : rawHex.replaceAll("[^0-9A-Fa-f]", "");
        boolean truncated = false;
        if (normalized.length() > MAX_HEX_CHARS) {
            normalized = normalized.substring(0, MAX_HEX_CHARS);
            truncated = true;
        }
        if ((normalized.length() & 1) != 0) normalized = normalized.substring(0, normalized.length() - 1);
        byte[] raw = fromHex(normalized);
        if (raw.length == 0) return new Decoded(normalized, "", "empty", false, truncated);

        byte[] derived = raw;
        String transform = "";
        String lowerHints = hints == null ? "" : hints.toLowerCase(Locale.ROOT);
        try {
            if (isGzip(raw) || lowerHints.contains("gzip")) {
                derived = readLimited(new GZIPInputStream(new ByteArrayInputStream(raw)));
                transform = "gzip";
            } else if (lowerHints.contains("deflate") || looksZlib(raw)) {
                try {
                    derived = inflate(raw, false);
                } catch (IOException wrappedFailure) {
                    derived = inflate(raw, true);
                }
                transform = "deflate";
            } else if (lowerHints.matches("(?s).*\\bbr\\b.*") || lowerHints.contains("brotli")) {
                derived = readLimited(new BrotliInputStream(new ByteArrayInputStream(raw)));
                transform = "brotli";
            }
        } catch (IOException ignored) {
            derived = raw;
            transform = "";
        }

        String text = decodeText(derived, StandardCharsets.UTF_8);
        String charset = "UTF-8";
        if (text == null) {
            String declaredCharset = declaredChineseCharset(lowerHints);
            if (declaredCharset != null) {
                text = decodeText(derived, Charset.forName(declaredCharset));
                charset = declaredCharset;
            }
        }
        if (text == null) {
            return new Decoded(normalized, "", transform.isEmpty() ? "binary/ciphertext" : transform + " binary",
                    true, truncated);
        }
        if (looksChunked(text) || lowerHints.contains("chunked")) {
            String unchunked = decodeChunked(text);
            if (unchunked != null) {
                text = unchunked;
                transform = transform.isEmpty() ? "chunked" : transform + "+chunked";
            }
        }
        String formatted = formatJson(text);
        if (!formatted.equals(text)) transform = transform.isEmpty() ? "json" : transform + "+json";
        String encoding = transform.isEmpty() ? charset : transform + " / " + charset;
        return new Decoded(normalized, formatted, encoding, false, truncated);
    }

    private static String declaredChineseCharset(String hints) {
        java.util.regex.Matcher matcher = java.util.regex.Pattern
                .compile("(?:^|[^a-z0-9])(gb18030|gbk|gb2312)(?:$|[^a-z0-9])")
                .matcher(hints);
        return matcher.find() ? matcher.group(1).toUpperCase(Locale.ROOT) : null;
    }

    private static byte[] fromHex(String hex) {
        byte[] data = new byte[hex.length() / 2];
        for (int i = 0; i < data.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) return new byte[0];
            data[i] = (byte) ((high << 4) | low);
        }
        return data;
    }

    private static String decodeText(byte[] data, Charset charset) {
        try {
            CharBuffer chars = charset.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data));
            String value = chars.toString();
            if (!isDisplayable(value)) return null;
            return value;
        } catch (CharacterCodingException ignored) {
            return null;
        }
    }

    private static boolean isDisplayable(String value) {
        if (value.isEmpty()) return true;
        int printable = 0;
        int controls = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t' || (!Character.isISOControl(c) && c != '\uFFFD')) {
                printable++;
            } else {
                controls++;
            }
        }
        return controls == 0 || printable * 100 / value.length() >= 85;
    }

    private static boolean isGzip(byte[] data) {
        return data.length > 2 && (data[0] & 0xff) == 0x1f && (data[1] & 0xff) == 0x8b;
    }

    private static boolean looksZlib(byte[] data) {
        if (data.length < 2) return false;
        int header = ((data[0] & 0xff) << 8) | (data[1] & 0xff);
        return (data[0] & 0x0f) == 8 && header % 31 == 0;
    }

    private static byte[] inflate(byte[] data, boolean nowrap) throws IOException {
        Inflater inflater = new Inflater(nowrap);
        try (InflaterInputStream input = new InflaterInputStream(new ByteArrayInputStream(data), inflater)) {
            return readLimited(input);
        } finally {
            inflater.end();
        }
    }

    private static byte[] readLimited(java.io.InputStream input) throws IOException {
        try (java.io.InputStream in = input; ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int count;
            while ((count = in.read(buffer)) >= 0) {
                if (output.size() + count > MAX_OUTPUT_BYTES) {
                    output.write(buffer, 0, MAX_OUTPUT_BYTES - output.size());
                    break;
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private static boolean looksChunked(String value) {
        int newline = value.indexOf("\r\n");
        if (newline <= 0 || newline > 12) return false;
        return value.substring(0, newline).matches("(?i)[0-9a-f]+(?:;.*)?");
    }

    private static String decodeChunked(String input) {
        StringBuilder output = new StringBuilder();
        int cursor = 0;
        try {
            while (cursor < input.length()) {
                int lineEnd = input.indexOf("\r\n", cursor);
                if (lineEnd < 0) return null;
                String sizeText = input.substring(cursor, lineEnd).split(";", 2)[0].trim();
                int size = Integer.parseInt(sizeText, 16);
                cursor = lineEnd + 2;
                if (size == 0) return output.toString();
                if (cursor + size > input.length()) return null;
                output.append(input, cursor, cursor + size);
                cursor += size;
                if (!input.startsWith("\r\n", cursor)) return null;
                cursor += 2;
            }
        } catch (NumberFormatException ignored) {
            return null;
        }
        return null;
    }

    private static String formatJson(String input) {
        String value = input.trim();
        try {
            if (value.startsWith("{") && value.endsWith("}")) return new org.json.JSONObject(value).toString(2);
            if (value.startsWith("[") && value.endsWith("]")) return new org.json.JSONArray(value).toString(2);
        } catch (Exception ignored) {
        }
        return input;
    }

    static final class Decoded {
        final String rawHex;
        final String text;
        final String encoding;
        final boolean binary;
        final boolean truncated;

        Decoded(String rawHex, String text, String encoding, boolean binary, boolean truncated) {
            this.rawHex = rawHex;
            this.text = text;
            this.encoding = encoding;
            this.binary = binary;
            this.truncated = truncated;
        }
    }
}
