let results = [];
let toolsState = {};
let shadowITState = { status: 'wait', found: [] };
let lastUpdateTimestamp = 0;
let shadowITChecked = false;
let pollingIntervalId = null;
let sunburstRoot = null;
let sunburstZoomNode = null;
let sunburstAncestorsStack = [];
let currentZoomPath = null;

// ------ 진입점 ------
document.addEventListener('DOMContentLoaded', scanMonitor);

async function scanMonitor() {
  let scanId;
  try {
    const res = await fetch('/status');
    const statusData = await res.json();
    scanId = statusData.scan_result_id;
    localStorage.setItem('scan_result_id', scanId);
  } catch (e) {
    console.warn('초기 상태 fetch 실패:', e);
    return;
  }
  shadowITState = { status: 'wait', found: [] };
  lastUpdateTimestamp = 0;
  shadowITChecked = false;
  initSunburstChart();

  if (pollingIntervalId !== null) return;
  pollingIntervalId = setInterval(async () => {
    let updated = false;
    try {
      const res = await fetch(`/status?scan_result_id=${scanId}`);
      if (res.ok) {
        const data = await res.json();
        if (data.results && data.results.length > 0) {
          const uniqueResults = {};
          for (const r of data.results) {
            if (!r || typeof r !== 'object') continue;
            const key = `${r.tool_id}_${r.step}`;
            if (!uniqueResults[key] || (r.timestamp || 0) > (uniqueResults[key].timestamp || 0)) {
              uniqueResults[key] = r;
            }
          }
          const deduped = Object.values(uniqueResults);
          const latestTimestamp = Math.max(...deduped.map(r => r.timestamp || 0));
          if (latestTimestamp > lastUpdateTimestamp) {
            results = deduped;
            lastUpdateTimestamp = latestTimestamp;
            toolsState = transformToToolsState(results);
            updated = true;
          }
          updateScanStatus(data.scan_status);
        }
      }
    } catch (e) {
      console.warn("상태 fetch 실패", e);
    }

    if (updated) {
      renderScanTreeAndShadow(results, shadowITState);
      renderResultTable(results);
      updateSunburstChart(toolsState);

      // zoom 상태 유지 (업데이트 후에도!)
      if (sunburstZoomNode) {
        const matchNode = sunburstRoot.descendants().find(
          n => n.data.name === sunburstZoomNode.data.name && n.depth === sunburstZoomNode.depth
        );
        if (matchNode) {
          applyZoomTransform(matchNode, sunburstRoot, d3.arc()
            .startAngle(d => d.x0)
            .endAngle(d => d.x1)
            .innerRadius(d => d.y0)
            .outerRadius(d => d.y1)
          );
          sunburstZoomNode = matchNode;
        }
      }
    }

    // ------ 모든 스캔이 끝나면 shadowIT 분석 및 폴링 중단 ------
    if (isAllScanFinished(results) && !shadowITChecked) {
      shadowITChecked = true;
      try {
        const res = await fetch(`/api/scan/${scanId}/shadowit`);
        if (res.ok) {
          shadowITState = await res.json();
        } else {
          shadowITState = { status: 'fail', found: [] };
        }
      } catch (err) {
        shadowITState = { status: 'fail', found: [] };
      }
      renderScanTreeAndShadow(results, shadowITState);

      // 폴링 정지
      if (pollingIntervalId !== null) {
        clearInterval(pollingIntervalId);
        pollingIntervalId = null;
      }
    }
  }, 2000);
}

function transformToToolsState(results) {
  const tools = {};
  results.forEach(r => {
    if (!tools[r.step]) tools[r.step] = [];
    tools[r.step].push({
      tool: r.tool,
      status: r.status,
      summary: r.summary,
      log: r.log,
      tool_id: r.tool_id,
    });
  });
  return tools;
}

function updateScanStatus(status) {
  const statusElement = document.getElementById('scan-status');
  if (statusElement) {
    statusElement.textContent = status;
    statusElement.className = `status ${status}`;
  }
}
function isAllScanFinished(results) {
  return results.length > 0 && results.every(r => r.status === 'success' || r.status === 'fail');
}

// --------- 트리 & Shadow IT ---------
function renderScanTreeAndShadow(results, shadowITState) {
  const tree = document.getElementById('scanTree');
  if (!tree) return;
  tree.innerHTML = '';
  const stepGroups = {};
  results.forEach(result => {
    if (!stepGroups[result.step]) stepGroups[result.step] = [];
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

  // ---- Shadow IT 컬럼 추가 ----
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

// --------- 결과 테이블 ---------
function renderResultTable(results) {
  const table = document.getElementById('resultTableBody');
  if (!table) return;
  table.innerHTML = '';
  results.forEach(result => {
    const tr = document.createElement('tr');
    const tdStep = document.createElement('td');
    tdStep.textContent = result.step;
    const tdTool = document.createElement('td');
    tdTool.textContent = `${result.tool} (#${result.tool_id})`;
    const tdStatus = document.createElement('td');
    tdStatus.textContent = result.status;
    if (result.status === 'success') tdStatus.classList.add('status-success');
    else if (result.status === 'fail') tdStatus.classList.add('status-fail');
    else if (result.status === 'in_progress') tdStatus.classList.add('status-in-progress');
    const tdDetail = document.createElement('td');
    const btn = document.createElement('button');
    btn.textContent = 'View Log';
    btn.classList.add('view-log-btn');
    btn.onclick = () => {
      document.getElementById('logContent').textContent = result.log || 'No log available.';
      document.getElementById('logPopup').classList.remove('hidden');
    };
    tdDetail.appendChild(btn);
    tr.appendChild(tdStep);
    tr.appendChild(tdTool);
    tr.appendChild(tdStatus);
    tr.appendChild(tdDetail);
    table.appendChild(tr);
  });
}

// =============== SUNBURST CHART ==================

function initSunburstChart() {
  const width = 600, height = 600;
  const radius = Math.min(width, height) / 2;
  const container = document.getElementById("sunburstChart");
  if (!container) return;
  container.innerHTML = '';
  
  const svg = d3.select(container)
    .append("svg")
    .attr("viewBox", `0 0 600 600`)
    .attr("preserveAspectRatio", "xMidYMid meet")
    .append("g")
    .attr("transform", `translate(300,300)`);

  // 중앙 원 추가
  svg.append("circle")
    .attr("r", radius / 3)  // 중앙 원의 크기
    .attr("fill", "none")
    .attr("pointer-events", "all")
    .style("cursor", "pointer")
    .on("click", () => {
      if (sunburstZoomNode && sunburstZoomNode.parent) {
        // 현재 노드의 부모 노드로 이동
        const parentNode = sunburstZoomNode.parent;
        
        // root로 돌아가는 경우
        if (parentNode === sunburstRoot) {
          sunburstZoomNode = null;
          updateSunburstChart(toolsState);
        } else {
          // 중간 레이어로 돌아가는 경우
          sunburstZoomNode = parentNode;
          applyZoomTransform(parentNode, sunburstRoot, arc);
          updateSunburstLabelOpacity();
        }
      }
    });

  window.sunburstSvg = svg;
  window.sunburstRadius = radius;
}

function updateSunburstChart(tools) {
  if (!tools) return;
  sunburstRoot = d3.hierarchy(toolsToSunburstHierarchy(tools))
    .sum(d => d.value || 0);
  
  const partition = d3.partition()
    .size([2 * Math.PI, window.sunburstRadius]);
  partition(sunburstRoot);

  if (sunburstZoomNode === null) sunburstAncestorsStack = [];
  const svg = window.sunburstSvg;
  let arcsGroup = svg.select("g.arcs");
  let labelsGroup = svg.select("g.labels");
  
  if (arcsGroup.empty()) {
    arcsGroup = svg.append("g").attr("class", "arcs");
    labelsGroup = svg.append("g").attr("class", "labels");
  }

  const arc = d3.arc()
    .startAngle(d => d.x0)
    .endAngle(d => d.x1)
    .innerRadius(d => Math.max(d.y0 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8))
    .outerRadius(d => Math.max(d.y1 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8));

  // Arcs
  const paths = arcsGroup.selectAll("path.arc")
    .data(sunburstRoot.descendants().slice(1), d => d.ancestors().map(dd => dd.data.name).join('/'));

  const enterPaths = paths.enter()
    .append("path")
    .attr("class", "arc")
    .attr("d", arc)
    .style("fill", getColorByDepth)
    .style("stroke", "white")
    .style("stroke-width", "1px")
    .style("cursor", "pointer")
    .on("click", (event, d) => {
      event.stopPropagation();
      if (d.children) {
        if (sunburstZoomNode !== d) {
          sunburstZoomNode = d;
          applyZoomTransform(d, sunburstRoot, arc);
          updateSunburstLabelOpacity();
        }
      }
    })
    .on("mousemove", (event, d) => showTooltip(event, d))
    .on("mouseleave", hideTooltip);

  paths.merge(enterPaths)
    .transition()
    .duration(750)
    .attr("d", arc)
    .style("fill", getColorByDepth);

  paths.exit().remove();

  // Labels
  const labelThreshold = 0.05;
  const labels = labelsGroup.selectAll("text.label")
    .data(sunburstRoot.descendants().slice(1)
      .filter(d => (d.x1 - d.x0) > labelThreshold),
      d => d.ancestors().map(dd => dd.data.name).join('/'));

  function computeTextPath(d) {
    const radius = Math.max(d.y0 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8) +
                  (Math.max(d.y1 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8) -
                   Math.max(d.y0 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8)) / 2;
    const startAngle = d.x0;
    const endAngle = d.x1;
    const angleRange = endAngle - startAngle;
    const midAngle = startAngle + angleRange / 2;
    const arcLength = angleRange * radius;
    const words = d.data.name.split(/\s+/);
    const maxCharsPerLine = Math.floor(arcLength / 7);
    let lines = [];
    let currentLine = words[0];
    for (let i = 1; i < words.length; i++) {
      if ((currentLine + " " + words[i]).length <= maxCharsPerLine) {
        currentLine += " " + words[i];
      } else {
        lines.push(currentLine);
        currentLine = words[i];
      }
    }
    lines.push(currentLine);
    return {
      radius,
      midAngle,
      lines
    };
  }

  const enterLabels = labels.enter()
    .append("text")
    .attr("class", "label")
    .style("font-size", "11px")
    .style("fill", "white")
    .style("pointer-events", "none");

  labels.merge(enterLabels)
    .each(function(d) {
      const self = d3.select(this);
      const textInfo = computeTextPath(d);
      const rotation = textInfo.midAngle * 180 / Math.PI - 90;
      const flip = rotation > 90 && rotation < 270;
      self.selectAll("tspan").remove();
      textInfo.lines.forEach((line, i) => {
        const lineHeight = 12;
        const yOffset = (i - (textInfo.lines.length - 1) / 2) * lineHeight;
        self.append("tspan")
          .attr("x", 0)
          .attr("dy", i === 0 ? 0 : lineHeight)
          .attr("transform", `translate(0,${yOffset})`)
          .style("text-anchor", "middle")
          .text(line);
      });
      self.attr("transform", `
        rotate(${rotation})
        translate(${textInfo.radius},0)
        ${flip ? "rotate(180)" : ""}
      `);
    })
    .style("opacity", function(d) {
      if (!sunburstZoomNode) return (d.x1 - d.x0) > labelThreshold ? 1 : 0;
      return d.ancestors().includes(sunburstZoomNode) || d.parent === sunburstZoomNode ? 1 : 0;
    });

  labels.exit().remove();
}

function updateSunburstLabelOpacity() {
  // 라벨 opacity만 따로 갱신
  const labelThreshold = 0.05;
  const labelsGroup = window.sunburstSvg.select("g.labels");
  labelsGroup.selectAll("text.label")
    .style("opacity", function(d) {
      if (!sunburstZoomNode) return (d.x1 - d.x0) > labelThreshold ? 1 : 0;
      return d.ancestors().includes(sunburstZoomNode) || d.parent === sunburstZoomNode ? 1 : 0;
    });
}

function applyZoomTransform(target, root, arc) {
  if (!target) return;
  
  root.each(d => {
    d.targetX0 = Math.max(0, Math.min(1, (d.x0 - target.x0) / (target.x1 - target.x0))) * 2 * Math.PI;
    d.targetX1 = Math.max(0, Math.min(1, (d.x1 - target.x0) / (target.x1 - target.x0))) * 2 * Math.PI;
    d.targetY0 = Math.max(0, d.y0 - target.y0);
    d.targetY1 = Math.max(0, d.y1 - target.y0);
  });

  const svg = window.sunburstSvg;
  const arcsGroup = svg.select("g.arcs");
  const labelsGroup = svg.select("g.labels");

  arcsGroup.selectAll("path.arc")
    .transition()
    .duration(750)
    .attrTween("d", function(d) {
      const i = d3.interpolate(
        {x0: d.x0, x1: d.x1, y0: d.y0, y1: d.y1},
        {x0: d.targetX0, x1: d.targetX1, y0: d.targetY0, y1: d.targetY1}
      );
      return t => {
        const b = i(t);
        d.x0 = b.x0;
        d.x1 = b.x1;
        d.y0 = b.y0;
        d.y1 = b.y1;
        return arc(d);
      };
    });

  labelsGroup.selectAll("text.label")
    .transition()
    .duration(750)
    .attrTween("transform", function(d) {
      const start = {
        x0: d.x0, x1: d.x1, y0: d.y0, y1: d.y1
      };
      const end = {
        x0: d.targetX0, x1: d.targetX1, y0: d.targetY0, y1: d.targetY1
      };
      const i = d3.interpolate(start, end);
      return function(t) {
        const b = i(t);
        const radius = Math.max(b.y0 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8) +
                      (Math.max(b.y1 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8) -
                       Math.max(b.y0 * 0.85 + window.sunburstRadius / 8, window.sunburstRadius / 8)) / 2;
        const startAngle = b.x0;
        const endAngle = b.x1;
        const angleRange = endAngle - startAngle;
        const midAngle = startAngle + angleRange / 2;
        const rotation = midAngle * 180 / Math.PI - 90;
        const flip = rotation > 90 && rotation < 270;
        return `
          rotate(${rotation})
          translate(${radius},0)
          ${flip ? "rotate(180)" : ""}
        `;
      }
    })
    .on("end", updateSunburstLabelOpacity);
  updateSunburstLabelOpacity();
}

function getColorByDepth(d) {
  const baseColors = {
    step: "#109CF1",
    tool: "#4CAF50",
    result: "#8192a6"
  };
  const statusColors = {
    success: "#4CAF50",
    fail: "#F7685B",
    in_progress: "#FFA000"
  };
  if (d.data.status) return statusColors[d.data.status] || baseColors.result;
  if (/^Step/.test(d.data.name)) return baseColors.step;
  if (d.depth === 0) return "#2C3E50";
  if (d.depth === 1) return baseColors.step;
  if (d.depth === 2) return baseColors.tool;
  return baseColors.result;
}

function showTooltip(event, d) {
  let tooltip = document.getElementById('sunburstTooltip');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.id = 'sunburstTooltip';
    tooltip.className = 'sunburst-tooltip';
    document.body.appendChild(tooltip);
  }
  tooltip.style.display = "block";
  tooltip.style.left = (event.pageX + 18) + "px";
  tooltip.style.top = (event.pageY - 20) + "px";
  tooltip.innerHTML =
    `<b>${d.data.name}</b><br>` +
    (d.data.status ? `Status: <span style="color:${d.data.status === 'success' ? '#4caf50' : d.data.status === 'fail' ? '#F7685B' : d.data.status === 'in_progress' ? '#FFA000' : '#BDBDBD'}">${d.data.status}</span><br>` : '') +
    (d.data.summary ? `Summary: ${d.data.summary}<br>` : '') +
    (d.value ? `Value: ${d.value}` : '');
}
function hideTooltip() {
  const tooltip = document.getElementById('sunburstTooltip');
  if (tooltip) tooltip.style.display = "none";
}

// --------- 도구 결과 파싱 ---------
function toolsToSunburstHierarchy(tools) {
  const root = { name: "SCAN", children: [] };
  let stepNum = 1;
  while (tools[stepNum]) {
    const stepTools = tools[stepNum].filter(t => t.status !== 'wait');
    const stepNode = {
      name: `Step ${stepNum}`,
      children: stepTools.map(tool => {
        const node = {
          name: tool.tool,
          status: tool.status,
          summary: tool.summary
        };
        if (tool.status === 'success' && tool.log) {
          const parsed = parseToolResults(tool.log);
          if (parsed.length > 0) {
            node.children = parsed.map(p => ({
              name: p.detail,
              type: p.type,
              status: "result",
              value: p.value
            }));
          } else {
            node.children = [{
              name: tool.summary,
              status: "result",
              value: 1
            }];
          }
        } else if (tool.status === 'fail') {
          node.children = [{
            name: tool.summary || 'Failed',
            status: 'fail',
            value: 1
          }];
        } else if (tool.status === 'in_progress') {
          node.value = 1;
        }
        return node;
      })
    };
    root.children.push(stepNode);
    stepNum++;
  }
  return root;
}

function parseToolResults(log) {
  const results = [];
  if (!log) return results;
  try {
    if (log.includes('Nmap scan')) {
      const portMatches = log.match(/(\d+)\/tcp\s+open\s+(\w+)/g) || [];
      portMatches.forEach(match => {
        const [port, service] = match.split(/\s+/);
        results.push({
          detail: `Port ${port.split('/')[0]} (${service})`,
          type: 'port',
          value: 5
        });
      });
    } else if (log.includes('S3 buckets')) {
      const bucketMatches = log.match(/Found: ([^\n]+)\nAccess: ([^\n]+)/g) || [];
      bucketMatches.forEach(match => {
        const [_, bucket, access] = match.match(/Found: (.+)\nAccess: (.+)/) || [];
        results.push({
          detail: `${bucket} (${access})`,
          type: 'bucket',
          value: 8
        });
      });
    } else if (log.includes('vulnerability scan')) {
      const vulnMatches = log.match(/\[(HIGH|MEDIUM|LOW)\] ([^\n]+)/g) || [];
      vulnMatches.forEach(match => {
        const [_, severity, desc] = match.match(/\[(HIGH|MEDIUM|LOW)\] (.+)/) || [];
        results.push({
          detail: `${severity}: ${desc}`,
          type: 'vulnerability',
          value: severity === 'HIGH' ? 10 : severity === 'MEDIUM' ? 7 : 4
        });
      });
    } else if (log.includes('cloud resources')) {
      const resourceMatches = log.match(/Found: ([^\n]+)/g) || [];
      resourceMatches.forEach(match => {
        const resource = match.replace('Found: ', '').trim();
        results.push({
          detail: resource,
          type: 'cloud_resource',
          value: 6
        });
      });
    }
  } catch (e) {
    console.error('Error parsing tool results:', e);
  }
  return results;
}

// ---- 로그 팝업 닫기 ----
function closeLogPopup() {
  document.getElementById('logPopup').classList.add('hidden');
}
