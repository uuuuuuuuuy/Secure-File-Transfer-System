const REFRESH_INTERVAL = 10000;
let bannerTimer = null;

function $(selector) {
  return document.querySelector(selector);
}

function createCell(content) {
  const td = document.createElement('td');
  if (content instanceof HTMLElement) {
    td.appendChild(content);
  } else {
    td.textContent = content ?? '-';
  }
  return td;
}

function renderStatus(ok) {
  const span = document.createElement('span');
  span.className = `status-pill ${ok ? 'ok' : 'pending'}`;
  span.textContent = ok ? '已确认' : '待确认';
  return span;
}

function hideBanner() {
  const banner = $('#banner');
  if (!banner) {
    return;
  }
  banner.hidden = true;
  banner.textContent = '';
  banner.className = 'banner';
}

function showBanner(message, variant = 'info') {
  const banner = $('#banner');
  if (!banner) {
    return;
  }
  banner.textContent = message;
  banner.hidden = false;
  banner.className = `banner ${variant}`;
  if (bannerTimer) {
    clearTimeout(bannerTimer);
  }
  bannerTimer = setTimeout(() => {
    hideBanner();
  }, 5000);
}

async function parseResponse(response) {
  const text = await response.text();
  let payload = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (error) {
      payload = { message: text };
    }
  }
  if (!response.ok) {
    const detail = payload.error || payload.message || `请求失败：${response.status}`;
    throw new Error(detail);
  }
  return payload;
}

async function fetchJson(url) {
  const response = await fetch(url);
  return parseResponse(response);
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body ?? {}),
  });
  return parseResponse(response);
}

function updateTotals(totals) {
  $('#total-clients').textContent = totals.clients ?? 0;
  $('#total-transfers').textContent = totals.transfers ?? 0;
  $('#total-verified').textContent = totals.verified ?? 0;
  $('#total-pending').textContent = totals.pending ?? 0;
}

function updateServerInfo(info) {
  const list = $('#server-hosts');
  if (list) {
    list.innerHTML = '';
    const hosts = info?.hosts ?? [];
    if (!hosts.length) {
      const empty = document.createElement('li');
      empty.textContent = '暂无可用地址';
      list.appendChild(empty);
    } else {
      hosts.forEach((host) => {
        const li = document.createElement('li');
        li.textContent = host;
        list.appendChild(li);
      });
    }
  }
  const tcpPort = $('#server-tcp-port');
  if (tcpPort) {
    tcpPort.textContent = info?.tcp_port ?? '-';
  }
  const httpPort = $('#server-http-port');
  if (httpPort) {
    httpPort.textContent = info?.http_port ?? '-';
  }
}

function renderClients(clients) {
  const tbody = $('#clients-body');
  tbody.innerHTML = '';
  if (!clients || !clients.length) {
    const empty = document.createElement('tr');
    empty.className = 'empty';
    const td = document.createElement('td');
    td.colSpan = 6;
    td.textContent = '暂无数据';
    empty.appendChild(td);
    tbody.appendChild(empty);
    return;
  }

  clients.forEach((client) => {
    const tr = document.createElement('tr');
    tr.appendChild(createCell(client.name || '-'));
    const idCell = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = client.client_id || '-';
    idCell.appendChild(code);
    tr.appendChild(idCell);
    tr.appendChild(createCell(client.last_seen_display || '-'));
    tr.appendChild(createCell(client.last_ip || '-'));
    tr.appendChild(createCell(client.has_public_key ? '已上传' : '未上传'));
    tr.appendChild(createCell(client.has_aes_key ? '已协商' : '未协商'));
    tbody.appendChild(tr);
  });
}

function renderTransfers(transfers) {
  const tbody = $('#transfers-body');
  tbody.innerHTML = '';
  if (!transfers || !transfers.length) {
    const empty = document.createElement('tr');
    empty.className = 'empty';
    const td = document.createElement('td');
    td.colSpan = 7;
    td.textContent = '暂无记录';
    empty.appendChild(td);
    tbody.appendChild(empty);
    return;
  }

  transfers.forEach((transfer) => {
    const tr = document.createElement('tr');
    tr.appendChild(createCell(transfer.received_at_display || '-'));
    tr.appendChild(createCell(`${transfer.client_name || '-'} (${transfer.client_id || '-'})`));
    tr.appendChild(createCell(transfer.file_name || '-'));
    const pathCell = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = transfer.path_name || '-';
    pathCell.appendChild(code);
    tr.appendChild(pathCell);
    tr.appendChild(createCell(transfer.client_ip || '-'));
    tr.appendChild(createCell(renderStatus(Boolean(transfer.crc_verified))));

    const actionCell = document.createElement('td');
    if (typeof transfer.row_id === 'number') {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'link-button';
      button.textContent = transfer.crc_verified ? '标记为待确认' : '确认 CRC';
      button.addEventListener('click', async () => {
        button.disabled = true;
        try {
          const data = await markTransfer(transfer.row_id, !transfer.crc_verified);
          if (data?.verified !== undefined) {
            const text = data?.message || (data.verified ? '已确认 CRC' : '已恢复待确认');
            showBanner(text, 'success');
          }
        } catch (error) {
          console.error('更新 CRC 状态失败', error);
          showBanner(error.message || '更新 CRC 状态失败', 'error');
        } finally {
          button.disabled = false;
        }
      });
      actionCell.appendChild(button);
    } else {
      actionCell.textContent = '-';
    }
    tr.appendChild(actionCell);

    tbody.appendChild(tr);
  });
}

async function refreshOverview() {
  try {
    const [overview, serverInfo] = await Promise.all([
      fetchJson('/api/overview'),
      fetchJson('/api/server-info'),
    ]);
    updateTotals(overview.totals || {});
    renderClients(overview.clients || []);
    renderTransfers(overview.transfers || []);
    updateServerInfo(serverInfo || {});
  } catch (error) {
    console.error('刷新数据失败', error);
    showBanner(error.message || '刷新数据失败', 'error');
  }
}

async function markTransfer(rowId, verified) {
  const data = await postJson(`/api/transfers/${rowId}/verify`, { verified });
  await refreshOverview();
  return data;
}

function setupControls() {
  $('#refresh-clients').addEventListener('click', refreshOverview);
  $('#refresh-transfers').addEventListener('click', refreshOverview);
}

function init() {
  setupControls();
  refreshOverview();
  setInterval(refreshOverview, REFRESH_INTERVAL);
}

document.addEventListener('DOMContentLoaded', init);
