const $ = (id) => document.getElementById(id);

const setText = (id, text) => {
  const el = $(id);
  if (el) el.textContent = text ?? "-";
};

const setMessage = (id, text, isError = false) => {
  const el = $(id);
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("error", Boolean(text) && isError);
};

const pushLog = (message) => {
  const log = $("log");
  if (!log) return;
  const item = document.createElement("li");
  item.textContent = `${new Date().toLocaleTimeString()} · ${message}`;
  log.prepend(item);
  while (log.children.length > 30) {
    log.removeChild(log.lastChild);
  }
};

const formatTime = (value) => {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString();
  } catch (error) {
    return value;
  }
};

const updateSummary = (data) => {
  setText("summary-server-tcp", data.serverEndpoint || "-");
  setText("summary-server-http", data.serverHttpEndpoint || "-");
  const portSource = data.serverHttpPortConfigured
    ? `transfer.info 配置 (${data.serverHttpPort})`
    : `默认端口 (${data.serverHttpPort})`;
  setText("summary-http-source", portSource);
  setText("summary-name", data.clientName);
  setText("summary-id", data.clientId);
  setText("summary-aes", data.hasAesKey ? "已协商" : "未协商");
  setText("summary-last-key", formatTime(data.lastKeyExchange));
  setText("summary-last-send", formatTime(data.lastSendAt));
  setText("summary-last-send-file", data.lastSendFile);
  setText("summary-file", data.filePath);
  setText("summary-fingerprint", data.publicKeyFingerprint);
  setText(
    "summary-key-created",
    data.publicKeyCreatedAt ? formatTime(data.publicKeyCreatedAt) : "-"
  );

  const serverForm = $("server-form");
  if (serverForm) {
    if (data.serverHost) serverForm.serverHost.value = data.serverHost;
    if (data.serverTcpPort)
      serverForm.serverTcpPort.value = data.serverTcpPort;
    if (Object.prototype.hasOwnProperty.call(data, "serverHttpPortConfigured")) {
      serverForm.serverHttpPort.value =
        data.serverHttpPortConfigured != null ? data.serverHttpPortConfigured : "";
    }
  }
};

const handleResponse = async (response) => {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = data && data.error ? data.error : "请求失败";
    throw new Error(error);
  }
  updateSummary(data);
  if (data.message) pushLog(data.message);
  return data;
};

const postJson = async (url, payload) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return handleResponse(response);
};

const postForm = async (url, formData) => {
  const response = await fetch(url, { method: "POST", body: formData });
  return handleResponse(response);
};

const fetchState = async () => {
  try {
    const response = await fetch("/api/state");
    const data = await response.json();
    updateSummary(data);
    return data;
  } catch (error) {
    pushLog(`获取状态失败：${error}`);
    throw error;
  }
};

const bindServerForm = () => {
  const form = $("server-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    setMessage("server-message", "");
    const payload = {
      serverHost: form.serverHost.value.trim(),
      serverTcpPort: form.serverTcpPort.value.trim(),
    };
    if (form.serverHttpPort.value !== "") {
      payload.serverHttpPort = form.serverHttpPort.value.trim();
    }
    try {
      const data = await postJson("/api/server", payload);
      setMessage("server-message", data.message || "服务器配置已保存");
    } catch (error) {
      setMessage("server-message", error.message, true);
    }
  });
};

const bindRegisterForm = () => {
  const form = $("register-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    setMessage("auth-message", "");
    try {
      const data = await postJson("/api/register", {
        clientName: form.clientName.value.trim(),
      });
      setMessage("auth-message", data.message || "注册成功");
    } catch (error) {
      setMessage("auth-message", error.message, true);
    }
  });
};

const bindLoginForm = () => {
  const form = $("login-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    setMessage("auth-message", "");
    try {
      const data = await postJson("/api/login", {
        clientName: form.clientName.value.trim(),
        clientId: form.clientId.value.trim(),
      });
      setMessage("auth-message", data.message || "登录成功");
    } catch (error) {
      setMessage("auth-message", error.message, true);
    }
  });
};

const bindKeyButtons = () => {
  const rotateBtn = $("generate-keys");
  if (rotateBtn) {
    rotateBtn.addEventListener("click", async () => {
      setMessage("key-message", "");
      try {
        const data = await postJson("/api/keys", {});
        setMessage("key-message", data.message || "已生成新的密钥对");
      } catch (error) {
        setMessage("key-message", error.message, true);
      }
    });
  }

  const exchangeBtn = $("key-exchange");
  if (exchangeBtn) {
    exchangeBtn.addEventListener("click", async () => {
      setMessage("key-message", "");
      try {
        const data = await postJson("/api/key-exchange", {});
        setMessage("key-message", data.message || "密钥交换成功");
      } catch (error) {
        setMessage("key-message", error.message, true);
      }
    });
  }
};

const bindFileForm = () => {
  const form = $("file-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!form.reportValidity()) return;
    setMessage("file-message", "");
    try {
      const data = await postForm("/api/upload-local", new FormData(form));
      setMessage("file-message", data.message || "文件已保存");
    } catch (error) {
      setMessage("file-message", error.message, true);
    }
  });
};

const bindSendButton = () => {
  const button = $("send-button");
  if (!button) return;
  button.addEventListener("click", async () => {
    setMessage("send-message", "正在发送，请稍候……");
    try {
      const data = await postJson("/api/send", {});
      setMessage("send-message", data.message || "文件已发送");
    } catch (error) {
      setMessage("send-message", error.message, true);
    }
  });
};

const init = async () => {
  await fetchState();
  bindServerForm();
  bindRegisterForm();
  bindLoginForm();
  bindKeyButtons();
  bindFileForm();
  bindSendButton();
};

document.addEventListener("DOMContentLoaded", init);
