const REFRESH_INTERVAL = 10000;

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

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `请求失败：${response.status}`);
  }
  return response.json();
}

function updateTotals(totals) {
  $('#total-clients').textContent = totals.clients ?? 0;
  $('#total-transfers').textContent = totals.transfers ?? 0;
  $('#total-verified').textContent = totals.verified ?? 0;
  $('#total-pending').textContent = totals.pending ?? 0;
}

function updateHosts(hosts, tcpPort) {
  const list = $('#server-hosts');
  list.innerHTML = '';
  if (!hosts || !hosts.length) {
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
  $('#server-tcp-port').textContent = tcpPort ?? '-';
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
    td.colSpan = 6;
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
    updateHosts(serverInfo.hosts || [], serverInfo.tcp_port);
  } catch (error) {
    console.error('刷新数据失败', error);
  }
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
