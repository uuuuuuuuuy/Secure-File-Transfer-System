function $(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const el = $(id);
  if (el) {
    el.textContent = text || "-";
  }
}

function setInputValue(id, value) {
  const input = $(id);
  if (!input) return;
  if (document.activeElement === input) return;
  if (value === null || typeof value === "undefined") {
    input.value = "";
  } else {
    input.value = value;
  }
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }
  try {
    return new Date(value).toLocaleString();
  } catch (error) {
    return value;
  }
}

function setMessage(id, text, isError = false) {
  const el = $(id);
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("error", Boolean(text) && isError);
}

function pushLog(message) {
  const log = $("log");
  if (!log) return;
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString()} · ${message}`;
  log.prepend(item);
}

async function fetchState() {
  try {
    const response = await fetch("/api/state");
    const data = await response.json();
    updateSummary(data);
  } catch (error) {
    pushLog(`获取状态失败：${error}`);
  }
}

function updateSummary(data) {
  setText("summary-server-host", data.serverHost);
  setText("summary-server", data.serverEndpoint);
  if (data.serverHttpEndpoint) {
    const suffix = data.serverHttpPortConfigured ? "" : "（默认端口）";
    setText("summary-server-http", `${data.serverHttpEndpoint}${suffix}`);
  } else if (data.serverHost) {
    setText("summary-server-http", `${data.serverHost}:${data.serverHttpPort}（默认端口）`);
  } else {
    setText("summary-server-http", null);
  }
  setText("summary-name", data.clientName);
  setText("summary-id", data.clientId);
  setText("summary-file", data.filePath);
  setText("summary-fingerprint", data.publicKeyFingerprint);
  setText("summary-key-created", formatDateTime(data.publicKeyCreatedAt));
  setText("summary-aes", data.hasAesKey ? "已协商" : "未协商");
  setText("summary-last-send", formatDateTime(data.lastSendAt));
  setText("summary-last-file", data.lastSendFile);

  setInputValue("server-host", data.serverHost || "");
  setInputValue("server-tcp-port", data.serverTcpPort || "");
  const httpPortValue = data.serverHttpPortConfigured;
  setInputValue("server-http-port", httpPortValue === null || typeof httpPortValue === "undefined" ? "" : httpPortValue);
}

async function parseResponse(res) {
  const text = await res.text();
  if (!text) {
    return { data: undefined, rawText: "" };
  }

  try {
    return { data: JSON.parse(text), rawText: "" };
  } catch (error) {
    return { data: undefined, rawText: text };
  }
}

function extractErrorMessage(data, rawText, res) {
  if (data && typeof data === "object") {
    if (typeof data.error === "string" && data.error.trim()) {
      return data.error.trim();
    }
    if (typeof data.message === "string" && data.message.trim()) {
      return data.message.trim();
    }
    if (typeof data.detail === "string" && data.detail.trim()) {
      return data.detail.trim();
    }
    if (Array.isArray(data.errors) && data.errors.length) {
      const first = data.errors[0];
      if (typeof first === "string" && first.trim()) {
        return first.trim();
      }
    }
  }

  if (typeof rawText === "string" && rawText.trim()) {
    const snippet = rawText.trim();
    return snippet.length > 200 ? `${snippet.slice(0, 200)}…` : snippet;
  }

  return `请求失败（HTTP ${res.status}）`;
}

async function postJson(url, payload) {
  let res;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    throw new Error(`无法连接到客户端服务：${message}`);
  }

  const { data, rawText } = await parseResponse(res);
  if (!res.ok) {
    throw new Error(extractErrorMessage(data, rawText, res));
  }
  const payload = data && typeof data === "object" ? data : {};
  updateSummary(payload);
  if (payload.message) {
    pushLog(payload.message);
  }
  return payload;
}

async function postForm(url, formData) {
  let res;
  try {
    res = await fetch(url, { method: "POST", body: formData });
  } catch (error) {
    const message = error && error.message ? error.message : String(error);
    throw new Error(`无法连接到客户端服务：${message}`);
  }

  const { data, rawText } = await parseResponse(res);
  if (!res.ok) {
    throw new Error(extractErrorMessage(data, rawText, res));
  }
  const payload = data && typeof data === "object" ? data : {};
  updateSummary(payload);
  if (payload.message) {
    pushLog(payload.message);
  }
  return payload;
}

function bindForms() {
  const serverForm = $("server-form");
  if (serverForm) {
    serverForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("server-message", "");
      const formData = new FormData(serverForm);
      try {
        const payload = {
          serverHost: formData.get("serverHost"),
          serverTcpPort: formData.get("serverTcpPort"),
          serverHttpPort: formData.get("serverHttpPort"),
        };
        const data = await postJson("/api/server", payload);
        setMessage("server-message", data.message || "服务器配置已更新");
      } catch (error) {
        setMessage("server-message", error.message, true);
      }
    });
  }

  const registerForm = $("register-form");
  if (registerForm) {
    registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("auth-message", "");
      try {
        const clientName = new FormData(registerForm).get("clientName");
        const data = await postJson("/api/register", { clientName });
        setMessage("auth-message", data.message || "注册成功");
      } catch (error) {
        setMessage("auth-message", error.message, true);
      }
    });
  }

  const loginForm = $("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("auth-message", "");
      const formData = new FormData(loginForm);
      try {
        const data = await postJson("/api/login", {
          clientName: formData.get("clientName"),
          clientId: formData.get("clientId"),
        });
        setMessage("auth-message", data.message || "登录成功");
      } catch (error) {
        setMessage("auth-message", error.message, true);
      }
    });
  }

  const keyButton = $("generate-keys");
  if (keyButton) {
    keyButton.addEventListener("click", async () => {
      setMessage("key-message", "");
      try {
        const data = await postJson("/api/keys", {});
        setMessage("key-message", data.message || "已生成新密钥");
      } catch (error) {
        setMessage("key-message", error.message, true);
      }
    });
  }

  const uploadKeyButton = $("upload-key");
  if (uploadKeyButton) {
    uploadKeyButton.addEventListener("click", async () => {
      setMessage("key-message", "");
      try {
        const data = await postJson("/api/key-exchange", {});
        setMessage("key-message", data.message || "密钥交换完成");
      } catch (error) {
        setMessage("key-message", error.message, true);
      }
    });
  }

  const fileForm = $("file-form");
  if (fileForm) {
    fileForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      setMessage("file-message", "");
      try {
        const formData = new FormData(fileForm);
        const data = await postForm("/api/upload-local", formData);
        setMessage("file-message", data.message || "文件已保存");
      } catch (error) {
        setMessage("file-message", error.message, true);
      }
    });
  }

  const sendButton = $("send-file");
  if (sendButton) {
    sendButton.addEventListener("click", async () => {
      setMessage("send-message", "");
      try {
        const data = await postJson("/api/send", {});
        const parts = [];
        if (data.message) {
          parts.push(data.message);
        }
        if (typeof data.serverCrc !== "undefined") {
          parts.push(`CRC ${data.serverCrc}`);
        }
        if (typeof data.serverFileSize !== "undefined") {
          parts.push(`原始大小 ${data.serverFileSize} 字节`);
        }
        setMessage("send-message", parts.join(" · ") || "文件已发送");
      } catch (error) {
        setMessage("send-message", error.message, true);
      }
    });
  }
}

function init() {
  fetchState();
  bindForms();
}

document.addEventListener("DOMContentLoaded", init);
