let stopFlag = false;
let exitFlag = false;
let isscanning = true;

let results = []; // 실제 scan 결과 배열

document.addEventListener('DOMContentLoaded', scan_show);

async function scan_show() {
  const type = localStorage.getItem('resource_type');
  const value = localStorage.getItem('target_value');
  if (!type || !value) {
    alert("스캔 정보가 없습니다. 홈으로 돌아갑니다.");
    window.location.href = '/';
    return;
  }

  // 스캔 현황/결과를 Flask API에서 가져오는 부분 (아래는 더미)
  let results = [];
  try {
    const res = await fetch('/status');
    if (res.ok) {
      const statusData = await res.json();
      // 여기서 statusData를 바탕으로 scan 현황 및 진행률 등을 표시
      // 예시: results = statusData.results; (구현에 따라 확장)
      // 임시로 더미 사용:
      results = [
        { step: 1, tool: 'Nmap', tool_id: 101, status: 'success', log: 'Open ports: 22, 80, 443', summary: '22, 80, 443 open' },
        { step: 2, tool: 'Nuclei', tool_id: 201, status: 'in_progress', log: '', summary: 'Scanning vulnerabilities...' }
      ];
    }
  } catch (e) {
    // 실패 시 더미
    results = [
      { step: 1, tool: 'Nmap', tool_id: 101, status: 'success', log: 'Open ports: 22, 80, 443', summary: '22, 80, 443 open' },
      { step: 2, tool: 'Nuclei', tool_id: 201, status: 'in_progress', log: '', summary: 'Scanning vulnerabilities...' }
    ];
  }

  renderScanTree(results);
  renderResultTable(results);

  const intervalId = setInterval(() => {
    renderScanTree(results);
    renderResultTable(results);
  }, 1000);

  // 7초 후 상태 업데이트
  setTimeout(() => {
    const s3 = results.find(r => r.tool === 'S3scanner');
    if (s3) {
      s3.status = 'success';
      s3.log = 'Found open bucket: company-public-data';
      s3.summary = 'company-public-data open';
    }
  }, 7000);

  // 3초 후 새 도구 추가
  setTimeout(() => {
    const newResult = {
      step: 2,
      tool: 'Nuclei',
      tool_id: 401,
      status: 'in_progress',
      log: '',
      summary: 'Running template scans...'
    };
    results.push(newResult);

    // 2초 후 상태 업데이트
    setTimeout(() => {
      newResult.status = 'success';
      newResult.log = 'Found: CVE-2021-1234, CVE-2022-5678';
      newResult.summary = '2 vulnerabilities detected';
    }, 2000);
  }, 3000);
}

// UI 렌더 함수는 동일
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