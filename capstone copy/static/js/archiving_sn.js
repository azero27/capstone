function formatDate(datetimeStr) {
  const date = new Date(datetimeStr);
  const dd = String(date.getDate()).padStart(2, '0');
  const mm = String(date.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed
  const yyyy = date.getFullYear();
  const hh = String(date.getHours()).padStart(2, '0');
  const min = String(date.getMinutes()).padStart(2, '0');
  return `${dd}-${mm}-${yyyy} ${hh}:${min}`;
}

function renderSnapshotList(data) {
  const container = document.getElementById('snapshotList');
  container.innerHTML = '';

  data.forEach(scan => {
    const div = document.createElement('div');
    div.className = 'snapshot-item';

    div.innerHTML = `
      <div class="snapshot-time">${formatDate(scan.start_time)}</div>
      <div class="snapshot-buttons">
        <button class="scan-btn" onclick="movetoSn_s(${scan.id})">SCAN view</button>
        <button class="info-btn" onclick="movetoSn_i(${scan.id})">INFO view</button>
      </div>
    `;

    container.appendChild(div);
  });
}

async function loadSnapshotList() {
  const res = await fetch('/api/snapshots');
  const data = await res.json();
  renderSnapshotList(data);
}

document.addEventListener("DOMContentLoaded", loadSnapshotList);

