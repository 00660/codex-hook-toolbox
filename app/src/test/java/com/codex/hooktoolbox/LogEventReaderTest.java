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
    public void keepsUtf8ChineseJsonForRequestAndResponse() throws Exception {
        JSONObject request = LogEventReader.parseLiveBlock("http-network.log",
                "event=Http.request\n"
                        + "time_ms=1786587000123\n"
                        + "direction=outbound\n"
                        + "request_body_hex=7b226d7367223a22e8afb7e6b182e4b8ade69687e6988ee69687222c226e6f7465223a22e58f91e98081e4bd93e9aa8c227d\n---\n");
        JSONObject response = LogEventReader.parseLiveBlock("http-network.log",
                "event=Http.response\n"
                        + "time_ms=1786587001123\n"
                        + "direction=inbound\n"
                        + "response_body_hex=7b226d7367223a22e59b9ee58c85e4b8ade69687e6988ee69687222c22e59586e59381223a22e6b58be8af95e59586e59381227d\n---\n");

        JSONObject requestPayload = request.getJSONArray("payloads").getJSONObject(0);
        JSONObject responsePayload = response.getJSONArray("payloads").getJSONObject(0);
        assertEquals("outbound", request.getString("direction"));
        assertEquals("inbound", response.getString("direction"));
        assertEquals("请求中文明文", new JSONObject(requestPayload.getString("text")).getString("msg"));
        assertEquals("发送体验", new JSONObject(requestPayload.getString("text")).getString("note"));
        assertEquals("回包中文明文", new JSONObject(responsePayload.getString("text")).getString("msg"));
        assertEquals("测试商品", new JSONObject(responsePayload.getString("text")).getString("商品"));
        assertEquals("json / UTF-8", requestPayload.getString("encoding"));
        assertEquals("json / UTF-8", responsePayload.getString("encoding"));
        assertFalse(requestPayload.getBoolean("binary"));
        assertFalse(responsePayload.getBoolean("binary"));
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
