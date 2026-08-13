package com.codex.hooktoolbox;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.zip.GZIPOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class PayloadDecoderTest {
    @Test
    public void convertsHexToVisibleAsciiWithoutDroppingRaw() {
        String hex = "4d616e69666573742d56657273696f6e3a20312e30";
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex(hex, "");

        assertEquals(hex, result.rawHex);
        assertEquals("Manifest-Version: 1.0", result.text);
        assertEquals("UTF-8", result.encoding);
        assertFalse(result.binary);
    }

    @Test
    public void decodesUtf8AndFormatsJson() {
        String value = "{\"name\":\"测试\",\"ok\":true}";
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex(hex(value.getBytes(StandardCharsets.UTF_8)), "json");

        assertTrue(result.text.contains("\"name\": \"测试\""));
        assertTrue(result.encoding.contains("json"));
        assertFalse(result.binary);
    }

    @Test
    public void fallsBackToGb18030() {
        byte[] value = "中文明文".getBytes(Charset.forName("GB18030"));
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex(hex(value), "");

        assertEquals("中文明文", result.text);
        assertEquals("GB18030", result.encoding);
    }

    @Test
    public void decodesGzip() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
            gzip.write("compressed body".getBytes(StandardCharsets.UTF_8));
        }
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex(hex(bytes.toByteArray()), "content-encoding=gzip");

        assertEquals("compressed body", result.text);
        assertTrue(result.encoding.startsWith("gzip"));
    }

    @Test
    public void marksNonTextAsBinary() {
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex("000102030405fffe", "");

        assertTrue(result.binary);
        assertEquals("", result.text);
        assertEquals("binary/ciphertext", result.encoding);
    }

    @Test
    public void decodesChunkedBody() {
        String chunked = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        PayloadDecoder.Decoded result = PayloadDecoder.decodeHex(hex(chunked.getBytes(StandardCharsets.UTF_8)), "chunked");

        assertEquals("Wikipedia", result.text);
        assertTrue(result.encoding.contains("chunked"));
    }

    @Test
    public void splitsRealLogRecordsWithoutLegacySeparators() {
        String log = "truncated_previous_hex\n"
                + "event=MessageDigest.update\ntime_ms=1\ninput_hex=4d616e6966657374\n"
                + "event=Cipher.doFinal\ntime_ms=2\noutput_hex=706c61696e74657874\n";

        String[] blocks = LogEventReader.splitBlocks(log);

        assertEquals(3, blocks.length);
        assertTrue(blocks[1].startsWith("event=MessageDigest.update"));
        assertTrue(blocks[2].startsWith("event=Cipher.doFinal"));
    }

    private static String hex(byte[] data) {
        StringBuilder value = new StringBuilder(data.length * 2);
        for (byte b : data) value.append(String.format(Locale.US, "%02x", b));
        return value.toString();
    }
}
