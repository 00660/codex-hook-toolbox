package com.codex.hooktoolbox;

import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public final class LogEventReaderTest {
    @Test
    public void parsesRequestAddressAndPlaintext() throws Exception {
        JSONObject event = LogEventReader.parseLiveBlock("http-network.log",
                "event=Http.request\n"
                        + "time_ms=1786587000123\n"
                        + "direction=outbound\n"
                        + "method=POST\n"
                        + "url=https://example.test/api\n"
                        + "request_body_hex=7b2261223a317d\n---\n");

        assertEquals("POST", event.getJSONObject("fields").getString("method"));
        assertEquals("https://example.test/api", event.getJSONObject("fields").getString("url"));
        assertEquals(1, new JSONObject(event.getJSONArray("payloads").getJSONObject(0).getString("text")).getInt("a"));
        assertFalse(event.has("raw"));
        assertFalse(event.getJSONObject("fields").has("request_body_hex"));
    }

    @Test
    public void keepsConnectAndDnsButMarksHighRateSocketIoAsMetadata() throws Exception {
        JSONObject connect = LogEventReader.parseLiveBlock("http-network.log",
                "event=Socket.connect\ntime_ms=1\nremote_address=192.0.2.1\nremote_port=443\n---\n");
        JSONObject dns = LogEventReader.parseLiveBlock("http-network.log",
                "event=Dns.resolve\ntime_ms=2\nhostname=example.test\n---\n");
        JSONObject receive = LogEventReader.parseLiveBlock("http-network.log",
                "event=Socket.recvmsg\ntime_ms=3\nbytes=64\n---\n");

        assertFalse(connect.getBoolean("metadata"));
        assertFalse(dns.getBoolean("metadata"));
        assertTrue(receive.getBoolean("metadata"));
    }
}
