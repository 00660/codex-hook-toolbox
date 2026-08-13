package com.codex.hooktoolbox;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import org.json.JSONObject;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private WebView webView;
    private ExecutorService worker;
    private TraceController traceController;
    private HookController hookController;
    private LogEventReader logReader;
    private ExportManager exportManager;

    @Override
    @SuppressLint({"SetJavaScriptEnabled", "JavascriptInterface"})
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        worker = Executors.newSingleThreadExecutor();
        traceController = new TraceController();
        hookController = new HookController();
        logReader = new LogEventReader();
        exportManager = new ExportManager(this, logReader);

        webView = new WebView(this);
        webView.setBackgroundColor(0xfff4f5f2);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(false);
        webView.getSettings().setAllowContentAccess(false);
        webView.getSettings().setAllowFileAccess(true);
        webView.getSettings().setAllowFileAccessFromFileURLs(false);
        webView.getSettings().setAllowUniversalAccessFromFileURLs(false);
        webView.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        webView.getSettings().setSupportZoom(false);
        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return !"file".equals(request.getUrl().getScheme());
            }
        });
        webView.addJavascriptInterface(new Bridge(), "CodexNative");
        setContentView(webView);
        webView.loadUrl("file:///android_asset/index.html");
    }

    @Override
    protected void onDestroy() {
        if (traceController != null) traceController.shutdown();
        if (worker != null) worker.shutdownNow();
        if (webView != null) {
            webView.removeJavascriptInterface("CodexNative");
            webView.destroy();
        }
        super.onDestroy();
    }

    private final class Bridge {
        @JavascriptInterface
        public void request(String requestText) {
            worker.execute(() -> {
                String id = "";
                JSONObject response = new JSONObject();
                try {
                    JSONObject request = new JSONObject(requestText);
                    id = request.optString("id", "");
                    String action = request.optString("action", "");
                    String pkg = request.optString("packageName", "");
                    switch (action) {
                        case "probe":
                            response = new RomProbe().probe(pkg);
                            break;
                        case "hot":
                            response = hookController.setHot(pkg, request.optBoolean("enabled"));
                            break;
                        case "art":
                            response = hookController.setArt(pkg, request.optBoolean("enabled"));
                            break;
                        case "launch":
                            response = hookController.launch(pkg);
                            break;
                        case "stopAll":
                            response = hookController.stopAll(pkg);
                            traceController.stop();
                            break;
                        case "logs":
                            response = logReader.read(pkg, request.optString("source", "all"),
                                    request.optInt("limit", 40), request.optBoolean("includeNoise", false));
                            break;
                        case "traceStart":
                            response = traceController.start(pkg, request.optString("scope", "uid"),
                                    request.optInt("duration", 5));
                            break;
                        case "traceStop":
                            response = traceController.stop();
                            break;
                        case "traceState":
                            response = traceController.state();
                            response.put("text", traceController.latestTrace());
                            break;
                        case "export":
                            response = exportManager.export(pkg, request.optString("type", ""));
                            break;
                        default:
                            response.put("ok", false);
                            response.put("error", "未知操作");
                    }
                } catch (Exception e) {
                    try {
                        response = new JSONObject();
                        response.put("ok", false);
                        response.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
                    } catch (Exception ignored) {
                    }
                }
                deliver(id, response);
            });
        }
    }

    private void deliver(String id, JSONObject result) {
        String script = "window.CodexApp&&window.CodexApp.onResult("
                + JSONObject.quote(id) + "," + result + ");";
        runOnUiThread(() -> {
            if (webView != null) webView.evaluateJavascript(script, null);
        });
    }
}
