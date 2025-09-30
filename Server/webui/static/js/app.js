const state = {
  publicKey: null,
  privateKey: null,
};

function setMessage(id, text, isError = false) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text || "";
  el.classList.toggle("error", Boolean(text) && isError);
}

function updateSessionSummary(data) {
  document.getElementById("summary-client-name").textContent = data.clientName || "-";
  document.getElementById("summary-client-id").textContent = data.clientId || "-";
  document.getElementById("summary-aes-status").textContent = data.hasAesKey ? "已就绪" : "未协商";
}

function refreshFiles() {
  fetch("/api/files")
    .then((res) => res.json())
    .then((payload) => {
      const tbody = document.getElementById("file-tbody");
      tbody.innerHTML = "";
      const files = payload.files || [];
      if (!files.length) {
        tbody.innerHTML = '<tr><td colspan="3" class="empty">暂无记录</td></tr>';
        return;
      }
      files.forEach((item) => {
        const tr = document.createElement("tr");
        const verifiedText = item.verified ? "已确认" : "待确认";
        tr.innerHTML = `<td>${item.file_name}</td><td>${item.file_path}</td><td>${verifiedText}</td>`;
        tbody.appendChild(tr);
      });
    })
    .catch((err) => {
      console.error(err);
    });
}

function updateCrcStatus(text) {
  document.getElementById("summary-crc-status").textContent = text;
}

function base64ToArrayBuffer(base64) {
  const cleaned = base64.replace(/\s+/g, "");
  const binary = window.atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function exportKey(key) {
  const exported = await window.crypto.subtle.exportKey("spki", key);
  return window.btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function exportPrivateKey(key) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", key);
  return window.btoa(String.fromCharCode(...new Uint8Array(exported)));
}

async function importPrivateKey(base64) {
  const keyBuffer = base64ToArrayBuffer(base64);
  const privateKey = await window.crypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    true,
    ["decrypt"],
  );
  state.privateKey = privateKey;
  return privateKey;
}

async function ensurePrivateKey() {
  if (state.privateKey) {
    return state.privateKey;
  }
  const field = document.getElementById("private-key");
  if (!field || !field.value.trim()) {
    throw new Error("尚未生成或导入私钥");
  }
  return importPrivateKey(field.value.trim());
}

async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
  state.publicKey = keyPair.publicKey;
  state.privateKey = keyPair.privateKey;
  const publicKeyBase64 = await exportKey(keyPair.publicKey);
  const privateKeyBase64 = await exportPrivateKey(keyPair.privateKey);
  document.getElementById("public-key").value = publicKeyBase64;
  const privateField = document.getElementById("private-key");
  if (privateField) {
    privateField.value = privateKeyBase64;
  }
  document.getElementById("key-message").textContent = "已生成新的密钥对，请复制并妥善保管私钥。";
  console.info("新的密钥对已生成，私钥仅保留在浏览器内存中。");
  console.info(privateKeyBase64);
}

async function decryptAesKey(encryptedBase64) {
  const privateKey = await ensurePrivateKey();
  const encryptedBytes = Uint8Array.from(window.atob(encryptedBase64), (c) => c.charCodeAt(0));
  const decrypted = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, encryptedBytes);
  return window.btoa(String.fromCharCode(...new Uint8Array(decrypted)));
}

function attachHandlers() {
  const privateField = document.getElementById("private-key");
  if (privateField) {
    privateField.addEventListener("input", () => {
      state.privateKey = null;
    });
  }

  document.getElementById("register-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage("register-message", "");
    const clientName = new FormData(event.currentTarget).get("clientName");
    const res = await fetch("/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ clientName }),
    });
    const payload = await res.json();
    if (!res.ok) {
      setMessage("register-message", payload.error || "注册失败", true);
      return;
    }
    setMessage("register-message", payload.message);
    document.getElementById("summary-client-id").textContent = payload.clientId;
    document.getElementById("summary-client-name").textContent = payload.clientName;
  });

  document.getElementById("login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage("login-message", "");
    const data = new FormData(event.currentTarget);
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        clientName: data.get("clientName"),
        clientId: data.get("clientId"),
      }),
    });
    const payload = await res.json();
    if (!res.ok) {
      setMessage("login-message", payload.error || "登录失败", true);
      return;
    }
    setMessage("login-message", payload.message);
    document.getElementById("summary-client-id").textContent = payload.clientId;
    document.getElementById("summary-client-name").textContent = payload.clientName;
    document.getElementById("summary-aes-status").textContent = payload.hasAesKey ? "已就绪" : "未协商";
    if (payload.encryptedAESKey) {
      try {
        await ensurePrivateKey();
        const aesKey = await decryptAesKey(payload.encryptedAESKey);
        document.getElementById("aes-key").value = aesKey;
      } catch (error) {
        console.warn(error);
        setMessage("key-message", error.message, true);
      }
    }
    refreshFiles();
  });

  document.getElementById("key-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage("key-message", "");
    const publicKey = document.getElementById("public-key").value.trim();
    if (!publicKey) {
      setMessage("key-message", "请先提供公钥", true);
      return;
    }
    const res = await fetch("/api/key-exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ publicKey }),
    });
    const payload = await res.json();
    if (!res.ok) {
      setMessage("key-message", payload.error || "密钥交换失败", true);
      return;
    }
    setMessage("key-message", payload.message);
    document.getElementById("summary-aes-status").textContent = payload.hasAesKey ? "已就绪" : "未协商";
    if (payload.encryptedAESKey) {
      try {
        await ensurePrivateKey();
        const aesKey = await decryptAesKey(payload.encryptedAESKey);
        document.getElementById("aes-key").value = aesKey;
      } catch (error) {
        console.warn(error);
        setMessage("key-message", error.message, true);
      }
    }
  });

  document.getElementById("generate-keypair").addEventListener("click", () => {
    generateKeyPair().catch((error) => {
      setMessage("key-message", error.message, true);
    });
  });

  document.getElementById("upload-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    setMessage("upload-message", "");
    const fileInput = document.getElementById("file-input");
    if (!fileInput.files.length) {
      setMessage("upload-message", "请选择文件", true);
      return;
    }
    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const base64 = window.btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
    const res = await fetch("/api/files", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fileName: file.name,
        fileSize: file.size,
        encryptedFile: base64,
      }),
    });
    const payload = await res.json();
    if (!res.ok) {
      setMessage("upload-message", payload.error || "上传失败", true);
      return;
    }
    const message = `${payload.message || "文件已处理"} CRC: ${payload.crc}`;
    setMessage("upload-message", message);
    updateCrcStatus(`CRC ${payload.crc}`);
    refreshFiles();
  });

  document.getElementById("ack-accept").addEventListener("click", () => sendAck(true));
  document.getElementById("ack-reject").addEventListener("click", () => sendAck(false));
  document.getElementById("refresh-files").addEventListener("click", refreshFiles);
}

async function sendAck(value) {
  setMessage("ack-message", "");
  const res = await fetch("/api/files/ack", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ verified: value }),
  });
  const payload = await res.json();
  if (!res.ok) {
    setMessage("ack-message", payload.error || "提交失败", true);
    return;
  }
  setMessage("ack-message", payload.message);
  refreshFiles();
}

function init() {
  attachHandlers();
  fetch("/api/session")
    .then((res) => res.json())
    .then((data) => {
      updateSessionSummary(data);
      refreshFiles();
    })
    .catch((error) => console.error(error));
}

document.addEventListener("DOMContentLoaded", init);
