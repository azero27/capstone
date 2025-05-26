function getScanIdFromUrl() {
  const match = window.location.pathname.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : 1;
}

document.addEventListener('DOMContentLoaded', async function () {
  // scanId는 URL 파라미터 등에서 추출 필요 (예시로 1 사용)
  const scanId = getScanIdFromUrl();
  const res = await fetch(`/api/snapshots/${scanId}/scan_result`);
  const results = await res.json();
  renderScanTree(results);
  renderResultTable(results);
});

function renderScanTree(results) {
  const tree = document.getElementById('scanTree');
  tree.innerHTML = '';

  const stepGroups = {};
  results.forEach(result => {
    if (!stepGroups[result.step]) {
      stepGroups[result.step] = [];
    }
    stepGroups[result.step].push(result);
  });

  for (const step of Object.keys(stepGroups).sort((a, b) => a - b)) {
    const column = document.createElement('div');
    column.className = 'scan-step-column';

    const stepLabel = document.createElement('div');
    stepLabel.textContent = `[Step ${step}]`;
    stepLabel.style.fontWeight = 'bold';
    stepLabel.style.marginBottom = '10px';
    column.appendChild(stepLabel);

    stepGroups[step].forEach(result => {
      const node = document.createElement('div');
      node.className = 'scan-node';

      const row = document.createElement('div');
      row.className = 'scan-row';

      const dot = document.createElement('div');
      dot.className = 'scan-dot';

      if (result.status === 'fail') {
        dot.classList.add('failed-dot');
      } else if (result.status === 'in_progress') {
        dot.classList.add('loading-dot');
      } else if (result.status === 'success') {
        dot.classList.add('success-dot');
      }

      const line = document.createElement('div');
      line.className = 'scan-line';

      if (result.status === 'fail') {
        line.classList.add('failed');
      } else if (result.status === 'success') {
        line.classList.add('completed');
      }

      const summary = document.createElement('div');
      summary.className = 'scan-summary';
      summary.innerText = result.summary;

      row.appendChild(dot);
      row.appendChild(line);
      row.appendChild(summary);

      const toolLabel = document.createElement('div');
      toolLabel.className = 'scan-tool';
      toolLabel.innerText = `${result.tool} (ID: ${result.tool_id})`;

      node.appendChild(row);
      node.appendChild(toolLabel);
      column.appendChild(node);
    });

    tree.appendChild(column);
  }
}

function renderResultTable(results) {
  const table = document.getElementById('resultTableBody');
  table.innerHTML = '';

  results.forEach((result) => {
    const tr = document.createElement('tr');

    const tdStep = document.createElement('td');
    tdStep.textContent = result.step;

    const tdTool = document.createElement('td');
    tdTool.textContent = `${result.tool} (#${result.tool_id})`;

    const tdStatus = document.createElement('td');
    tdStatus.textContent = result.status;

    if (result.status === 'success') {
      tdStatus.classList.add('status-success');
    } else if (result.status === 'fail') {
      tdStatus.classList.add('status-fail');
    } else if (result.status === 'in_progress') {
      tdStatus.classList.add('status-in-progress');
    }

    const tdDetail = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'View Log';
    btn.classList.add('view-log-btn');
    btn.onclick = () => {
      document.getElementById('logContent').textContent = result.log || 'No log available.';
    };
    tdDetail.appendChild(btn);

    tr.appendChild(tdStep);
    tr.appendChild(tdTool);
    tr.appendChild(tdStatus);
    tr.appendChild(tdDetail);

    table.appendChild(tr);
  });
}
