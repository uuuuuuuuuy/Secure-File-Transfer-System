const REFRESH_INTERVAL = 5000;

const state = {
  selectedClientId: null,
  clients: [],
  refreshTimer: null,
};

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return `${date.toLocaleString()}`;
}

function formatSize(bytes) {
  const num = Number(bytes);
  if (Number.isNaN(num) || num <= 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(Math.floor(Math.log(num) / Math.log(1024)), units.length - 1);
  const size = num / 1024 ** exponent;
  return `${size.toFixed(size >= 100 || exponent === 0 ? 0 : 1)} ${units[exponent]}`;
}

function renderStatusPill(text, variant) {
  const pill = document.createElement("span");
  pill.classList.add("status-pill", variant);
  pill.textContent = text;
  return pill;
}

function createClientStatus(client) {
  if (client.hasAesKey) {
    return renderStatusPill("AES 已就绪", "ready");
  }
  if (client.hasPublicKey) {
    return renderStatusPill("等待 AES 下发", "pending");
  }
  return renderStatusPill("尚未上传公钥", "error");
}

function clearElement(el) {
  while (el.firstChild) {
    el.removeChild(el.firstChild);
  }
}

function renderOverview(stats) {
  document.getElementById("stat-clients").textContent = stats.clientCount ?? 0;
  document.getElementById("stat-transfers").textContent = stats.transferCount ?? 0;
  document.getElementById("stat-verified").textContent = stats.verifiedCount ?? 0;
}

function renderClients(clients) {
  const tbody = document.getElementById("clients-tbody");
  clearElement(tbody);

  if (!clients.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">暂无客户端</td></tr>';
    return;
  }

  clients.forEach((client) => {
    const tr = document.createElement("tr");
    if (client.clientId === state.selectedClientId) {
      tr.classList.add("is-selected");
    }
    tr.dataset.clientId = client.clientId;
    const idCell = document.createElement("td");
    const idCode = document.createElement("code");
    idCode.textContent = client.clientId;
    idCell.appendChild(idCode);
    tr.appendChild(idCell);

    const nameCell = document.createElement("td");
    nameCell.textContent = client.clientName || "-";
    tr.appendChild(nameCell);

    const seenCell = document.createElement("td");
    seenCell.textContent = formatDate(client.lastSeen);
    tr.appendChild(seenCell);

    const ipCell = document.createElement("td");
    ipCell.textContent = client.lastIp || "-";
    tr.appendChild(ipCell);

    const countCell = document.createElement("td");
    countCell.textContent = String(client.fileCount ?? 0);
    tr.appendChild(countCell);

    const statusCell = document.createElement("td");
    statusCell.appendChild(createClientStatus(client));
    tr.appendChild(statusCell);
    tr.addEventListener("click", () => {
      if (state.selectedClientId === client.clientId) {
        state.selectedClientId = null;
      } else {
        state.selectedClientId = client.clientId;
      }
      updateTransferFilter();
      refreshTransfers();
      renderClients(state.clients);
    });
    tbody.appendChild(tr);
  });
}

function renderTransfers(transfers) {
  const tbody = document.getElementById("transfers-tbody");
  clearElement(tbody);

  if (!transfers.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty">暂无文件传输记录</td></tr>';
    return;
  }

  transfers.forEach((item) => {
    const tr = document.createElement("tr");
    const timeCell = document.createElement("td");
    timeCell.textContent = formatDate(item.receivedAt);
    tr.appendChild(timeCell);

    const clientCell = document.createElement("td");
    const nameBlock = document.createElement("div");
    nameBlock.textContent = item.clientName || "-";
    const idCode = document.createElement("code");
    idCode.textContent = item.clientId;
    clientCell.appendChild(nameBlock);
    clientCell.appendChild(idCode);
    tr.appendChild(clientCell);

    const nameCell = document.createElement("td");
    nameCell.textContent = item.fileName;
    tr.appendChild(nameCell);

    const sizeCell = document.createElement("td");
    sizeCell.classList.add("file-size");
    sizeCell.textContent = formatSize(item.fileSize);
    tr.appendChild(sizeCell);

    const pathCell = document.createElement("td");
    pathCell.textContent = item.savedPath;
    tr.appendChild(pathCell);

    const ipCell = document.createElement("td");
    ipCell.textContent = item.sourceIp || "-";
    tr.appendChild(ipCell);

    const statusCell = document.createElement("td");
    const status = item.verified
      ? renderStatusPill("已确认", "ready")
      : renderStatusPill("待确认", "pending");
    statusCell.appendChild(status);
    tr.appendChild(statusCell);
    tbody.appendChild(tr);
  });
}

function updateTransferFilter() {
  const label = document.getElementById("transfer-filter");
  if (!state.selectedClientId) {
    label.textContent = "当前显示：全部客户端";
    return;
  }
  const target = state.clients.find((item) => item.clientId === state.selectedClientId);
  if (!target) {
    label.textContent = "当前显示：全部客户端";
    state.selectedClientId = null;
    return;
  }
  label.textContent = `当前显示：${target.clientName || "未命名客户端"}（ID：${target.clientId}）`;
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`请求失败：${response.status}`);
  }
  return response.json();
}

async function refreshOverview() {
  try {
    const data = await fetchJson("/api/overview");
    renderOverview(data);
  } catch (error) {
    console.error("获取概览失败", error);
  }
}

async function refreshClients() {
  try {
    const data = await fetchJson("/api/clients");
    state.clients = data.clients || [];
    if (state.selectedClientId) {
      const exists = state.clients.some((client) => client.clientId === state.selectedClientId);
      if (!exists) {
        state.selectedClientId = null;
      }
    }
    renderClients(state.clients);
    updateTransferFilter();
  } catch (error) {
    console.error("获取客户端列表失败", error);
  }
}

async function refreshTransfers() {
  const params = new URLSearchParams();
  if (state.selectedClientId) {
    params.set("clientId", state.selectedClientId);
    params.set("limit", "100");
  } else {
    params.set("limit", "50");
  }
  const query = params.toString();
  try {
    const url = query ? `/api/transfers?${query}` : "/api/transfers";
    const data = await fetchJson(url);
    renderTransfers(data.transfers || []);
  } catch (error) {
    console.error("获取传输记录失败", error);
  }
}

async function refreshAll() {
  await Promise.all([refreshOverview(), refreshClients()]);
  await refreshTransfers();
}

function scheduleAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
  }
  state.refreshTimer = setInterval(() => {
    refreshOverview();
    refreshClients().then(refreshTransfers);
  }, REFRESH_INTERVAL);
}

function init() {
  document.getElementById("refresh-all").addEventListener("click", () => {
    refreshAll();
  });

  const openStorageButton = document.getElementById("open-storage");
  if (openStorageButton) {
    openStorageButton.addEventListener("click", () => {
      const browser = window.open("/files-browser", "_blank");
      if (browser) {
        browser.opener = null;
      }
    });
  }

  refreshAll().then(() => {
    scheduleAutoRefresh();
  });
}

document.addEventListener("DOMContentLoaded", init);
