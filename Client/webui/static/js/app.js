function $(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const el = $(id);
  if (el) {
    el.textContent = text || "-";
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
  setText("summary-server", data.serverEndpoint);
  setText("summary-name", data.clientName);
  setText("summary-id", data.clientId);
  setText("summary-file", data.filePath);
  setText("summary-fingerprint", data.publicKeyFingerprint);
  setText("summary-key-created", data.publicKeyCreatedAt ? new Date(data.publicKeyCreatedAt).toLocaleString() : "-");
  setText("summary-aes", data.hasAesKey ? "已协商" : "未协商");
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || "请求失败");
  }
  updateSummary(data);
  if (data.message) {
    pushLog(data.message);
  }
  return data;
}

async function postForm(url, formData) {
  const res = await fetch(url, { method: "POST", body: formData });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || "请求失败");
  }
  updateSummary(data);
  if (data.message) {
    pushLog(data.message);
  }
  return data;
}

function bindForms() {
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
}

function init() {
  fetchState();
  bindForms();
}

document.addEventListener("DOMContentLoaded", init);
