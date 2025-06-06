let stopFlag = false;
let exitFlag = false;
let isscanning = true;

let results = []; 

document.addEventListener('DOMContentLoaded', function () {
  scan_show(); // 페이지 완전히 로드된 후 실행
});

// 스캔 결과 페이지 로드시 실행
function scan_show() {
  const ip = localStorage.getItem('targetIP');
  if (!ip) {
    alert("IP 정보가 없습니다. 홈으로 돌아갑니다.");
    window.location.href = 'home.html'; // 또는 적절한 경로
    return;
  }

  console.log("스캔 대상 IP:", ip);

  results = [
    {
      step: 1,
      tool: 'Nmap',
      status: 'success',
      log: 'Open ports: 22, 80, 443',
      summary: '22, 80, 443 open'
    },
    {
      step: 1,
      tool: 'Nikto',
      status: 'fail',
      log: 'Connection timeout to host',
      summary: 'Connection timeout'
    },
    {
      step: 2,
      tool: 'Gobuster',
      status: 'in_progress',
      log: '',
      summary: 'Scanning...'
    }
  ];

  renderScanTree(results);
  renderResultTable(results);

  const intervalId = setInterval(() => {
    renderScanTree(results);
    renderResultTable(results);
  }, 1000);

  setTimeout(() => {
    const gobuster = results.find(r => r.tool === 'Gobuster');
    if (gobuster) {
      gobuster.status = 'success';
      gobuster.log = 'Discovered: /admin, /login, /uploads';
      gobuster.summary = '/admin, /login, /uploads found';
    }
  }, 7000);
  setTimeout(() => {
    const gobuster = results.find(r => r.tool === 'Gobuster');
    if (gobuster) {
      gobuster.status = 'success';
      gobuster.log = 'Discovered: /admin, /login, /uploads';
      gobuster.summary = '/admin, /login, /uploads found';
    }
  }, 7000);
};

// 3초 후 첫 번째 추가 (in_progress -> 2초 뒤에 success)
setTimeout(() => {
  const newResult1 = {
    step: 2,
    tool: 'Wappalyzer',
    status: 'in_progress',
    log: '',
    summary: 'Detecting technologies...'
  };
  results.push(newResult1);
  console.log('3초 후 추가:', newResult1);

  // 2초 후 상태 변경
  setTimeout(() => {
    newResult1.status = 'success';
    newResult1.log = 'Detected: Apache, jQuery';
    newResult1.summary = 'Apache, jQuery found';
    console.log('5초 시점 업데이트:', newResult1);
  }, 2000);
}, 3000);

// 6초 후 두 번째 추가 (in_progress -> 4초 뒤에 fail)
setTimeout(() => {
  const newResult2 = {
    step: 2,
    tool: 'Dirsearch',
    status: 'in_progress',
    log: '',
    summary: 'Enumerating directories...'
  };
  results.push(newResult2);
  console.log('6초 후 추가:', newResult2);

  // 4초 후 상태 변경
  setTimeout(() => {
    newResult2.status = 'fail';
    newResult2.log = 'Error: Too many redirects';
    newResult2.summary = 'Too many redirects';
    console.log('10초 시점 업데이트:', newResult2);
  }, 4000);
}, 6000);

function renderScanTree(results) {
  const tree = document.getElementById('scanTree');
  tree.innerHTML = '';

  // step 기준으로 그룹화
  const stepGroups = {};
  results.forEach(result => {
    if (!stepGroups[result.step]) {
      stepGroups[result.step] = [];
    }
    stepGroups[result.step].push(result);
  });

  // 그룹 순서대로 열 구성
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
      toolLabel.innerText = result.tool;

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

  results.forEach((result, index) => {
    const tr = document.createElement('tr');

    const tdStep = document.createElement('td');
    tdStep.textContent = result.step;

    const tdTool = document.createElement('td');
    tdTool.textContent = result.tool;

    const tdStatus = document.createElement('td');
    tdStatus.textContent = result.status;

    const tdDetail = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'View Log';
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

