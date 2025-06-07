let results = []; // 실제 scan 결과 배열
let shadowITState = { status: 'wait', found: [] }; // Shadow IT 상태
let shadowITChecked = false; // Shadow IT 검사를 이미 했는지
let lastUpdateTimestamp = 0; // 마지막 업데이트 시간 추적
let pollingIntervalId = null;

document.addEventListener('DOMContentLoaded', scan_show);

async function handleManualScan() {
  // Get the current resource type from localStorage
  const resourceType = localStorage.getItem('resource_type');
  
  if (!resourceType) {
    alert('스캔 대상이 설정되지 않았습니다. 먼저 스캔 대상을 입력해주세요.');
    window.location.href = '/';
    return;
  }

  try {
    const response = await fetch('/api/oneoff_scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        type: resourceType
      })
    });

    if (!response.ok) {
      throw new Error('일회성 스캔 요청 실패');
    }

    const data = await response.json();
    console.log('일회성 스캔 시작됨:', data);
    
    // Store the task ID for tracking
    localStorage.setItem('scan_result_id', data.task_id);
    
    // Start monitoring the scan results
    scan_show();
    
    alert('일회성 스캔이 시작되었습니다.');

  } catch (error) {
    console.error('일회성 스캔 요청 중 오류:', error);
    alert('일회성 스캔 요청 중 오류가 발생했습니다: ' + error.message);
  }
}

async function scan_show() {
  // 먼저 status API에서 최신 상태와 scan_result_id를 가져옵니다
  const res = await fetch('/status');  // ✅ fetch 추가
  const statusData = await res.json(); // ✅ 이제 에러 안 남

  const scanId = statusData.scan_result_id; // ✅ 최신 scan_result_id 가져오기
  localStorage.setItem('scan_result_id', scanId);

  shadowITState = { status: 'wait', found: [] };
  lastUpdateTimestamp = 0;

  if (pollingIntervalId !== null) return;

  pollingIntervalId = setInterval(async () => {
    const updated = await updateScanResults(scanId);

    if (updated) {
      renderScanTree(results);
      renderResultTable(results);
    }

    if (isAllScanFinished(results) && !shadowITChecked) {
      shadowITChecked = true;
      await updateShadowITState(scanId);
      renderScanTree(results);
    }
  }, 2000);
}

async function updateScanResults(scanId) {
  if (!scanId) return false;
  try {
    const res = await fetch(`/status?scan_result_id=${scanId}`);
    if (res.ok) {
      const statusData = await res.json();
      
      // 결과가 없으면 종료
      if (!statusData.results || statusData.results.length === 0) {
        return false;
      }

      // 타임스탬프 확인 (각 결과의 타임스탬프 중 가장 최신 값)
      const latestTimestamp = Math.max(
        ...statusData.results
          .filter(r => r && typeof r === 'object')
          .map(r => r.timestamp || 0)
      );
      
      // 새로운 결과가 있는 경우에만 업데이트
      if (latestTimestamp > lastUpdateTimestamp) {
        const newResults = deduplicateResults(statusData.results);
        
        // 상태 업데이트
        results = newResults;
        lastUpdateTimestamp = latestTimestamp;
        
        // 스캔 상태 업데이트
        updateScanStatus(statusData.scan_status);
        
        return true;
      }
    }
  } catch (e) {
    console.warn("[스캔 결과 fetch 실패]", e);
  }
  return false;
}

// 중복 제거 함수 개선
function deduplicateResults(newResults) {
  const uniqueResults = {};
  
  // 타임스탬프 기준으로 최신 결과만 유지
  for (const result of newResults) {
    if (!result || typeof result !== 'object') continue;
    
    const key = `${result.tool_id}_${result.step}`;
    if (!uniqueResults[key] || (result.timestamp || 0) > (uniqueResults[key].timestamp || 0)) {
      uniqueResults[key] = result;
    }
  }
  
  return Object.values(uniqueResults);
}

// 스캔 상태 업데이트 함수
function updateScanStatus(status) {
  const statusElement = document.getElementById('scan-status');
  if (statusElement) {
    statusElement.textContent = status;
    statusElement.className = `status ${status}`;
  }
}

// 모든 스캔이 끝났는지? (in_progress가 없음)
function isAllScanFinished(results) {
  return results.length > 0 && results.every(r => r.status === 'success' || r.status === 'fail');
}

// Shadow IT 상태 업데이트 (스캔 종료 후 한 번만)
async function updateShadowITState(scanId) {
  if (!scanId) return;
  try {
    const res = await fetch(`/api/scan/${scanId}/shadowit`);
    if (res.ok) {
      const data = await res.json();
      // data = { status: 'success'|'in_progress'|'fail', found: [...] }
      shadowITState = data;
    } else {
      shadowITState = { status: 'fail', found: [] };
    }
  } catch (err) {
    shadowITState = { status: 'fail', found: [] };
    console.warn("[Shadow IT 상태 fetch 실패]", err);
  }
}

// ScanTree 렌더 함수 (Shadow IT 열 포함)
function renderScanTree(results) {
  const tree = document.getElementById('scanTree');
  tree.innerHTML = '';

  const stepGroups = {};
  results.forEach(result => {
    if (!stepGroups[result.step]) stepGroups[result.step] = [];
    stepGroups[result.step].push(result);
  });

  // 각 Step 열 생성
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

      if (result.status === 'fail') dot.classList.add('failed-dot');
      else if (result.status === 'in_progress') dot.classList.add('loading-dot');
      else if (result.status === 'success') dot.classList.add('success-dot');

      const line = document.createElement('div');
      line.className = 'scan-line';
      if (result.status === 'fail') line.classList.add('failed');
      else if (result.status === 'success') line.classList.add('completed');

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

  // ----------- Shadow IT 열 추가 (가장 오른쪽) -----------
  const shadowColumn = document.createElement('div');
  shadowColumn.className = 'scan-step-column';
  const shadowLabel = document.createElement('div');
  shadowLabel.textContent = `[Shadow IT]`;
  shadowLabel.style.fontWeight = 'bold';
  shadowLabel.style.marginBottom = '10px';
  shadowLabel.style.color = '#F7685B';
  shadowColumn.appendChild(shadowLabel);

  const node = document.createElement('div');
  node.className = 'scan-node';
  const row = document.createElement('div');
  row.className = 'scan-row';

  const dot = document.createElement('div');
  dot.className = 'scan-dot';

  let summary = document.createElement('div');
  summary.className = 'scan-summary';

  if (shadowITState.status === 'wait') {
    dot.style.backgroundColor = '#ddd';
    summary.innerText = '모든 스캔 종료 후 분석 시작';
  } else if (shadowITState.status === 'in_progress') {
    dot.classList.add('loading-dot');
    summary.innerText = 'Shadow IT 분석 중...';
  } else if (shadowITState.status === 'success') {
    dot.classList.add('success-dot');
    summary.innerHTML = shadowITState.found && shadowITState.found.length > 0
      ? `<b>발견:</b> ${shadowITState.found.join('<br><br>')}`
      : `<b>발견된 Shadow IT 없음</b>`;
  } else {
    dot.classList.add('failed-dot');
    summary.innerText = '실패';
  }

  row.appendChild(dot);
  row.appendChild(summary);
  node.appendChild(row);
  shadowColumn.appendChild(node);
  tree.appendChild(shadowColumn);
}

// 결과 테이블 렌더 함수
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
