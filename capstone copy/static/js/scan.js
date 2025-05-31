let stopFlag = false;
let exitFlag = false;
let isscanning = true;

let results = []; // 실제 scan 결과 배열
let displayedToolIds = new Set(); // 중복 방지용 

let shadowResults = []; // Shadow IT 분석 결과 저장용
let displayedShadowParts = new Set(); // 중복 방지용 

let renderResultHashes = new Set(); 

document.addEventListener('DOMContentLoaded', scan_show);

async function scan_show() {
  const type = localStorage.getItem('resource_type');
  const value = localStorage.getItem('target_value');
  const scanId = localStorage.getItem('scan_result_id');

  /*
  if (!type || !value) {
    alert("스캔 정보가 없습니다. 홈으로 돌아갑니다.");
    window.location.href = '/';
    return;
  }

  */
 
  try {
    const res = await fetch(`/status?scan_result_id=${scanId}`);
    if (res.ok) {
      const statusData = await res.json();
      // 여기서 statusData를 바탕으로 scan 현황 및 진행률 등을 표시
      // 예시: results = statusData.results; (구현에 따라 확장)
      results = statusData.results || [];
    }
  } catch (e) {
      console.warn("[초기 상태 불러오기 실패]", e);
  }

  renderScanTree(results);
  renderResultTable(results);

  const shadowParts = ['nuclei', 'nmap', 's3'];

  setInterval(async () => {
    const scanId = localStorage.getItem('scan_result_id');
    if (!scanId) return;

    // 1. Redis 등 캐시된 도구 실행 결과 먼저 가져옴
    try {
      const res = await fetch(`/status?scan_result_id=${scanId}`);
      if (res.ok) {
        const data = await res.json();

        if (Array.isArray(data.results)) {
          for (const r of data.results) {
            const hash = `${r.tool_id}-${r.step}-${r.summary}`;
            if (!renderResultHashes.has(hash)) {
              renderResultHashes.add(hash);
              results.push(r);
            }
          }

          console.log('[✅ TOOL CACHE FETCHED]');
          results.forEach((r, i) => {
            console.log(`▶️ [${i}] Tool=${r.tool}, Status=${r.status}, Step=${r.step}`);
          });

          renderScanTree(results);
          renderResultTable(results);
        }
      }
    } catch (err) {
      console.warn('[❌ 도구 결과 fetch 실패]', err);
    }

    // 2. shadow 분석 결과를 Redis 기반 API로 동적 요청
    try {
      const res = await fetch(`/status`);
      if (res.ok) {
        const data = await res.json(); // { nmap: {...}, nuclei: {...}, s3: {...} }

        for (const part of shadowParts) {
          const shadowId = `shadow-${part}`;

          if (!displayedShadowParts.has(shadowId) && data[part]) {
            shadowResults.push({
              component: part,
              status: 'success',
              summary: `[${part}] Shadow 분석 완료`,
              detail: JSON.stringify(data[part], null, 2)
            });
            displayedShadowParts.add(shadowId);
            renderShadowResultTable(shadowResults);
          }
        }
      }
    } catch (err) {
      console.warn('[ERROR] shadow 분석 결과 fetch 실패', err);
    }
  }, 10000);


  const intervalId = setInterval(() => {
    renderScanTree(results);
    renderResultTable(results);
  }, 1000);
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