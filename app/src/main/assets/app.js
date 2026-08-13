(function () {
  "use strict";
  var state = { source: "all", scope: "uid", page: "overview", traceTimer: null,
    eventTimer: null, eventLoading: false, eventSignature: "", status: null };
  var pending = new Map();
  var sequence = 0;
  var $ = function (selector) { return document.querySelector(selector); };
  var $$ = function (selector) { return Array.prototype.slice.call(document.querySelectorAll(selector)); };
  var pkg = function () { return $("#package").value.trim(); };

  function request(action, data) {
    var id = "r" + Date.now() + "_" + (++sequence);
    var payload = Object.assign({ id: id, action: action, packageName: pkg() }, data || {});
    return new Promise(function (resolve, reject) {
      pending.set(id, { resolve: resolve, reject: reject });
      if (!window.CodexNative) {
        pending.delete(id);
        reject(new Error("原生桥接不可用"));
        return;
      }
      window.CodexNative.request(JSON.stringify(payload));
    });
  }

  window.CodexApp = {
    onResult: function (id, result) {
      var job = pending.get(id);
      if (!job) return;
      pending.delete(id);
      if (result && result.ok) job.resolve(result);
      else job.reject(new Error(result && result.error ? result.error : "操作失败"));
    }
  };

  function toast(message, error) {
    var node = $("#toast");
    node.textContent = message;
    node.className = error ? "show error" : "show";
    clearTimeout(node.timer);
    node.timer = setTimeout(function () { node.className = ""; }, 2600);
  }

  async function execute(button, action) {
    try {
      if (button) button.disabled = true;
      return await action();
    } catch (error) {
      toast(error.message, true);
      throw error;
    } finally {
      if (button) button.disabled = false;
    }
  }

  function formatBytes(value) {
    var bytes = Number(value) || 0;
    var units = ["B", "KiB", "MiB", "GiB"];
    var index = 0;
    while (bytes >= 1024 && index < units.length - 1) { bytes /= 1024; index++; }
    return (bytes < 10 && index ? bytes.toFixed(1) : Math.round(bytes)) + " " + units[index];
  }

  function dot(id, ok) { $(id).className = ok ? "ok" : "bad"; }

  async function probe() {
    var result = await request("probe");
    state.status = result;
    $("#root-state").textContent = result.ok ? "可用" : "不可用";
    dot("#root-dot", result.ok);
    $("#process-count").textContent = result.process_count || 0;
    dot("#process-dot", Number(result.process_count) > 0);
    $("#watchdog-state").textContent = result.watchdog_module ? "存在" : "缺失";
    dot("#watchdog-dot", result.watchdog_module);
    $("#capture-target").textContent = result.packageName;
    $("#hot-toggle").checked = Boolean(result.hot_marker);
    $("#art-toggle").checked = (String(result.art_debug) === "1" && result.art_debug_pkg === result.packageName)
      || (String(result.art_persist) === "true" && result.art_persist_pkg === result.packageName)
      || (result.art_marker && result.art_marker_pkg === result.packageName);
    $("#size-java").textContent = formatBytes(result.log_java_bytes);
    $("#size-conscrypt").textContent = formatBytes(result.log_conscrypt_bytes);
    $("#size-boringssl").textContent = formatBytes(result.log_boringssl_bytes);
    $("#size-http").textContent = formatBytes(result.log_http_bytes);
    $("#dex-files").textContent = result.art_files || 0;
    $("#dex-size").textContent = formatBytes(result.art_bytes);
    $("#trace-node").textContent = result.trace_writable ? "可读写" : "不可用";
    renderBaseline(result);
    return result;
  }

  function renderBaseline(result) {
    var rows = [
      ["root uid", result.root_uid],
      ["目标 UID", result.uid == null ? "未安装" : result.uid],
      ["目标进程数", result.process_count],
      ["Trace 节点", result.trace_state || "不可见"],
      ["ART APEX", result.art_library ? "存在" : "缺失"],
      ["ART debug", (result.art_debug || "") + " / " + (result.art_debug_pkg || "")],
      ["ART persist", (result.art_persist || "") + " / " + (result.art_persist_pkg || "")],
      ["ART marker", result.art_marker ? result.art_marker_pkg || "存在" : "未启用"],
      ["Crypto APEX", result.crypto_library ? "存在" : "缺失"],
      ["Hot marker", result.hot_marker ? result.hot_marker_value || "存在" : "未启用"],
      ["看门狗模块", result.watchdog_module ? "存在" : "缺失"]
    ];
    $("#baseline").innerHTML = rows.map(function (row) {
      return '<div class="baseline-row"><span>' + escapeHtml(String(row[0]))
        + '</span><b>' + escapeHtml(String(row[1] == null ? "" : row[1])) + '</b></div>';
    }).join("");
    $("#baseline-json").textContent = JSON.stringify(result, null, 2);
  }

  function escapeHtml(value) {
    return value.replace(/[&<>"']/g, function (c) {
      return { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c];
    });
  }

  function sourceLabel(source) {
    return { "java-crypto.log":"JAVA", "conscrypt-crypto.log":"CONSCRYPT",
      "boringssl-crypto.log":"BORINGSSL", "http-network.log":"HTTP" }[source] || source;
  }

  function formatTime(time) {
    if (!time) return "--:--:--";
    return new Date(Number(time)).toLocaleTimeString("zh-CN", {
      hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit", fractionalSecondDigits:3
    });
  }

  function renderEvents(result) {
    $("#event-count").textContent = result.events.length + " 条事件";
    $("#filtered-count").textContent = "过滤 " + result.filtered + " 条噪声";
    var signature = result.source + "|" + result.includeNoise + "|" + result.events.map(function (event) {
      return event.source + ":" + event.timeMs + ":" + event.event + ":" + event.raw.length;
    }).join("|");
    if (signature === state.eventSignature) return;
    state.eventSignature = signature;
    if (!result.events.length) {
      $("#events").innerHTML = '<div class="empty-state"><svg><use href="#activity"/></svg><p>没有可展示事件</p></div>';
      return;
    }
    $("#events").innerHTML = result.events.map(function (event, eventIndex) {
      var fields = event.fields || {};
      var meta = ["pid", "thread", "algorithm", "op", "method", "url", "response_code"]
        .filter(function (key) { return fields[key]; })
        .map(function (key) { return "<span>" + escapeHtml(key) + ": <b>" + escapeHtml(fields[key]) + "</b></span>"; })
        .join("");
      var payloads = (event.payloads || []).map(function (payload, payloadIndex) {
        var id = "payload-" + eventIndex + "-" + payloadIndex;
        var text = payload.binary ? "[二进制或密文，未强制转码]" : payload.text;
        return '<details class="payload"><summary><span>' + escapeHtml(payload.field) + '</span><span>'
          + escapeHtml(payload.encoding) + " · " + Math.floor(payload.rawHex.length / 2) + ' B</span></summary>'
          + '<div class="payload-tabs"><button class="active" data-view="text" data-payload="' + id
          + '">派生明文</button><button data-view="hex" data-payload="' + id + '">原始 Hex</button></div>'
          + '<pre id="' + id + '" data-text="' + encodeURIComponent(text || "") + '" data-hex="'
          + encodeURIComponent(payload.rawHex) + '">' + escapeHtml(text || "") + "</pre></details>";
      }).join("");
      return '<article class="event"><div class="event-head"><span class="source-tag">'
        + escapeHtml(sourceLabel(event.source)) + '</span><span class="event-name">' + escapeHtml(event.event)
        + '</span><time class="event-time">' + formatTime(event.timeMs) + '</time></div><div class="event-meta">'
        + '<span>方向: <b>' + escapeHtml(event.direction) + "</b></span>" + meta + "</div>" + payloads + "</article>";
    }).join("");
  }

  async function loadEvents(button) {
    if (state.eventLoading) return;
    var requestedSource = state.source;
    var requestedNoise = $("#include-noise").checked;
    state.eventLoading = true;
    try {
      if (button) button.disabled = true;
      var result = await request("logs", { source: requestedSource, limit: 40,
        includeNoise: requestedNoise });
      if (requestedSource === state.source && requestedNoise === $("#include-noise").checked) {
        renderEvents(result);
      }
    } catch (error) {
      toast(error.message, true);
    } finally {
      if (button) button.disabled = false;
      state.eventLoading = false;
      if (requestedSource !== state.source || requestedNoise !== $("#include-noise").checked) loadEvents();
    }
  }

  function updateEventPolling() {
    clearInterval(state.eventTimer);
    state.eventTimer = null;
    if (state.page !== "events" || !$("#auto-events").checked) return;
    state.eventTimer = setInterval(function () {
      if (!document.hidden && !$("#events details[open]")) loadEvents();
    }, 2000);
  }

  async function pollTrace() {
    try {
      var result = await request("traceState");
      $("#trace-status").textContent = result.running ? "运行中" : result.reason;
      $("#trace-elapsed").textContent = result.elapsed + " / " + result.duration + " 秒";
      $("#trace-lines").textContent = result.lines + " 条";
      $("#trace-progress").max = Math.max(3, result.duration || 3);
      $("#trace-progress").value = result.elapsed || 0;
      if (result.text) $("#trace-output").textContent = result.text;
      if (!result.running) {
        clearInterval(state.traceTimer);
        state.traceTimer = null;
        await probe();
      }
    } catch (error) {
      clearInterval(state.traceTimer);
      state.traceTimer = null;
      toast(error.message, true);
    }
  }

  $$(".bottom-nav button").forEach(function (button) {
    button.addEventListener("click", function () {
      $$(".bottom-nav button").forEach(function (item) { item.classList.toggle("active", item === button); });
      $$(".page").forEach(function (page) { page.classList.toggle("active", page.dataset.page === button.dataset.target); });
      state.page = button.dataset.target;
      $("#page-title").textContent = {overview:"控制台",events:"实时事件",trace:"受控 Trace",
        export:"证据导出",baseline:"真实基线"}[button.dataset.target];
      if (state.page === "events") loadEvents();
      updateEventPolling();
    });
  });

  $("#refresh").addEventListener("click", function (event) { execute(event.currentTarget, probe); });
  $("#launch").addEventListener("click", function (event) {
    execute(event.currentTarget, async function () {
      await request("launch"); toast("目标应用已启动"); setTimeout(probe, 800);
    });
  });
  $("#hot-toggle").addEventListener("change", function (event) {
    var toggle = event.currentTarget;
    execute(toggle, async function () {
      await request("hot", { enabled: toggle.checked }); await probe();
      toast(toggle.checked ? "Crypto / HTTP 采集已启用" : "Crypto / HTTP 采集已停止");
    }).catch(probe);
  });
  $("#art-toggle").addEventListener("change", function (event) {
    var toggle = event.currentTarget;
    execute(toggle, async function () {
      await request("art", { enabled: toggle.checked }); await probe();
      toast(toggle.checked ? "ART DEX 采集已启用，重启目标后生效" : "ART DEX 采集已停止");
    }).catch(probe);
  });
  $("#stop-all").addEventListener("click", function (event) {
    execute(event.currentTarget, async function () {
      await request("stopAll"); await probe(); toast("全部采集已停止");
    });
  });
  $("#reload-events").addEventListener("click", function (event) { loadEvents(event.currentTarget); });
  $("#auto-events").addEventListener("change", function () {
    updateEventPolling();
    if (this.checked) loadEvents();
  });
  $("#include-noise").addEventListener("change", function () {
    state.eventSignature = "";
    loadEvents();
  });
  $$("#source-filter button").forEach(function (button) {
    button.addEventListener("click", function () {
      $$("#source-filter button").forEach(function (item) { item.classList.toggle("active", item === button); });
      state.source = button.dataset.source;
      state.eventSignature = "";
      loadEvents();
    });
  });
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden && state.page === "events") loadEvents();
  });
  $("#events").addEventListener("click", function (event) {
    var button = event.target.closest("[data-view]");
    if (!button) return;
    var pre = document.getElementById(button.dataset.payload);
    Array.prototype.slice.call(button.parentNode.querySelectorAll("button")).forEach(function (item) {
      item.classList.toggle("active", item === button);
    });
    pre.textContent = decodeURIComponent(button.dataset.view === "hex" ? pre.dataset.hex : pre.dataset.text);
  });
  $$(".trace-controls [data-scope]").forEach(function (button) {
    button.addEventListener("click", function () {
      $$(".trace-controls [data-scope]").forEach(function (item) { item.classList.toggle("active", item === button); });
      state.scope = button.dataset.scope;
    });
  });
  $("#trace-duration").addEventListener("input", function (event) {
    $("#duration-value").textContent = event.target.value + " 秒";
  });
  $("#trace-start").addEventListener("click", function (event) {
    execute(event.currentTarget, async function () {
      var result = await request("traceStart", { scope: state.scope, duration: Number($("#trace-duration").value) });
      $("#trace-status").textContent = "运行中";
      $("#trace-output").textContent = "Trace 正在采集，结束后显示输出。";
      clearInterval(state.traceTimer);
      state.traceTimer = setInterval(pollTrace, 1000);
      await pollTrace();
      toast("Trace 已限定到 " + result.scope);
    });
  });
  $("#trace-stop").addEventListener("click", function (event) {
    execute(event.currentTarget, async function () {
      await request("traceStop"); await pollTrace(); toast("Trace 已停止");
    });
  });
  $$("[data-export]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      execute(event.currentTarget, async function () {
        $("#export-result").textContent = "正在整理并校验产物…";
        var result = await request("export", { type: button.dataset.export });
        $("#export-result").textContent = result.name + "\n文件 " + result.files + " 个 · "
          + formatBytes(result.bytes) + "\nSHA256 " + result.sha256;
        toast("导出完成");
      });
    });
  });
  probe().catch(function (error) { toast(error.message, true); });
}());
