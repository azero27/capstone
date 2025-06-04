let selectedDates = [];
let viewstart = null;
let viewend = null;
let filteredTimelineData = [];
let scatterChart = null;

const RESOURCE_TYPES = [
  'EC2', 'S3', 'RDS', 'Lambda', 'VPC', 'SecurityGroup', 
  'IAM', 'CloudFront', 'Route53', 'ECS'
];

// ========== API Calls ==========
async function loadTimelineNodes(start, end) {
  try {
  const res = await fetch('/api/timeline_nodes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ start, end })
  });
    const data = await res.json();
    // Sort by date in descending order (most recent first)
    return data.sort((a, b) => new Date(b.date) - new Date(a.date));
  } catch (error) {
    console.error('Error loading timeline nodes:', error);
    return [];
  }
}

async function loadTimelineDiff(start, end) {
  try {
  const res = await fetch('/api/timeline_diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ start, end })
  });
    return await res.json();
  } catch (error) {
    console.error('Error loading timeline diff:', error);
    return [];
  }
}

async function loadResourceDiff(resource, start, end) {
  const res = await fetch('/api/resource_diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resource, start, end })
  });
  return res.json();
}

// ========== Chart Functions ==========
function updateChart(data) {
  if (!scatterChart) return;

  const datasets = [
    {
      label: 'Shadow IT',
      data: data.filter(d => d.type === 'shadow'),
      backgroundColor: '#000000',
      pointStyle: 'circle',
      radius: 8
    },
    {
      label: 'Added',
      data: data.filter(d => d.type === 'added'),
      backgroundColor: '#FF0000',
      pointStyle: 'rectRot',
      radius: 8
    },
    {
      label: 'Removed',
      data: data.filter(d => d.type === 'removed'),
      backgroundColor: '#0000FF',
      pointStyle: 'triangle',
      radius: 8
    }
  ].filter(dataset => dataset.data.length > 0);

  scatterChart.data.datasets = datasets;
  
  // Update y-axis labels based on available data
  const uniqueResources = [...new Set(data.map(d => d.resource))];
  scatterChart.options.scales.y.labels = uniqueResources;

  // Update time scale based on data range
  if (data.length > 0) {
    const dates = data.map(d => new Date(d.x));
    const minDate = new Date(Math.min(...dates));
    const maxDate = new Date(Math.max(...dates));
    
    scatterChart.options.scales.x.min = minDate;
    scatterChart.options.scales.x.max = maxDate;
  }

  scatterChart.update();
}

// ========== Timeline Functions ==========
async function renderTimeline() {
  const container = document.getElementById("timelineList");
  if (!container) return;
  
  container.innerHTML = "";

  try {
    // Get data from API
    filteredTimelineData = await loadTimelineNodes(viewstart, viewend);
    
    // Update chart
    const chartData = convertToChartData(filteredTimelineData);
    updateChart(chartData);

    // Render timeline items
  filteredTimelineData
  .sort((a, b) => new Date(a.date) - new Date(b.date)) // 오래된 게 먼저
  .forEach((entry, index) => {
    const item = document.createElement("div");
    item.className = "timeline-item";

    const dot = document.createElement("div");
    dot.className = "timeline-dot";
      if (selectedDates.includes(entry.date)) {
        dot.classList.add("selected");
      }
      
      // Make dot clickable with proper event listener
      dot.addEventListener('click', async () => {
        await toggleSelectDot(entry.date, dot);
      });

    const line = document.createElement("div");
    line.className = "timeline-line";

    const text = document.createElement("div");
      text.className = "timeline-text";
      text.innerHTML = `${formatDate(entry.date)}<br>${entry.rsc}: ${entry.dif}`;

    item.appendChild(dot);
      if (index < filteredTimelineData.length - 1) {
        item.appendChild(line);
      }
    item.appendChild(text);
      container.appendChild(item);
    });
  } catch (error) {
    console.error('Error rendering timeline:', error);
  }
}

function convertToChartData(timelineData) {
  return timelineData.flatMap(entry => {
    const changes = [];
    const date = new Date(entry.date);
    
    // Determine the type based on the diff text
    let type = 'added';
    if (entry.type === 'shadow' || 
        entry.dif.includes('unauthorized') || 
        entry.dif.includes('suspicious') || 
        entry.dif.includes('public access')) {
      type = 'shadow';
    } else if (entry.dif.includes('removed') || 
               entry.dif.includes('disabled') || 
               entry.dif.includes('terminated')) {
      type = 'removed';
    }
    
    changes.push({
      x: date,
      y: entry.rsc,
      type: type,
      resource: entry.rsc,
      description: entry.dif
    });
    
    return changes;
  });
}

// ========== Selection & Diff Functions ==========
async function toggleSelectDot(date, dot) {
  try {
    const index = selectedDates.indexOf(date);
    if (index === -1) {
      if (selectedDates.length < 2) {
        selectedDates.push(date);
        dot.classList.add("selected");
        
        // If we have 2 dates, show diff immediately
        if (selectedDates.length === 2) {
          await showDiff();
        }
      }
    } else {
      selectedDates.splice(index, 1);
      dot.classList.remove("selected");
      document.getElementById('popup').classList.add('hidden');
    }
  } catch (error) {
    console.error('Error toggling dot:', error);
  }
}

// ========== Filter Functions ==========
async function applyViewFilter() {
  const startInput = document.getElementById('viewStart');
  const endInput = document.getElementById('viewEnd');
  
  if (!startInput || !endInput) return;

  viewstart = startInput.value ? new Date(startInput.value).toISOString() : null;
  viewend = endInput.value ? new Date(endInput.value).toISOString() : null;

  // Clear any existing selections
  selectedDates = [];
  document.getElementById('popup')?.classList.add('hidden');

  try {
    // Get filtered data
    filteredTimelineData = await loadTimelineNodes(viewstart, viewend);
    
    // Update both timeline and chart
    const chartData = convertToChartData(filteredTimelineData);
    updateChart(chartData);
    renderTimeline();
  } catch (error) {
    console.error('Error applying view filter:', error);
  }
}

// ========== Utility Functions ==========
function formatDate(dtStr) {
  const d = new Date(dtStr);
  const date = `${d.getDate().toString().padStart(2, '0')}-${(d.getMonth() + 1).toString().padStart(2, '0')}-${d.getFullYear()}`;
  const time = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
  return `${date} ${time}`;
}

// ========== Initialization ==========
document.addEventListener('DOMContentLoaded', () => {
  // Initialize close button listener
  const closeBtn = document.querySelector('.close-btn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      const popup = document.getElementById('popup');
      if (popup) {
        popup.classList.add('hidden');
        // Clear selections
    selectedDates = [];
        document.querySelectorAll('.timeline-dot.selected').forEach(dot => {
          dot.classList.remove('selected');
        });
      }
    });
  }

  // Set default date range for last 24 hours
  const endDate = new Date();
  const startDate = new Date(endDate);
  startDate.setHours(endDate.getHours() - 24);

  const startInput = document.getElementById('viewStart');
  const endInput = document.getElementById('viewEnd');
  
  if (startInput && endInput) {
    startInput.value = startDate.toISOString().slice(0, 16);
    endInput.value = endDate.toISOString().slice(0, 16);
  }

  // Initialize chart and timeline
  initializeChart();
  renderTimeline();
});

function summarizeChangesByResource(accumulatedDiffs) {
  const summary = {};
  accumulatedDiffs.forEach(diff => {
    const resource = diff.resource || diff.rsc || "Unknown";
    const desc = diff.description || diff.dif || "";
    if (!summary[resource]) summary[resource] = [];
    // 중복 제거
    if (!summary[resource].includes(desc)) {
      summary[resource].push(desc);
    }
  });
  return summary;
}

// 팝업에 Changes Summary와 상세 diff 동시 출력
async function showDiff() {
  try {
    const [start, end] = selectedDates.sort();

    // 1. 두 노드 사이 timelineData만 필터
    const nodesBetween = filteredTimelineData.filter(node => {
      const nodeDate = new Date(node.date);
      return nodeDate >= new Date(start) && nodeDate <= new Date(end);
    }).sort((a, b) => new Date(a.date) - new Date(b.date));

    // 2. 리소스별로 변화 정리
    const resourceGroups = {};
    nodesBetween.forEach(node => {
      const resource = node.rsc || node.resource || "Unknown";
      const desc = node.dif || node.description || "";
      if (!resourceGroups[resource]) resourceGroups[resource] = [];
      // 중복 설명 제거
      if (!resourceGroups[resource].includes(desc)) {
        resourceGroups[resource].push(desc);
      }
    });

    // 3. 팝업에 표시
    const popup = document.getElementById('popup');
    const content = document.getElementById('popupContent');
    if (!popup || !content) return;
    content.innerHTML = '';

    // --- Changes Summary Section ---
    const summarySection = document.createElement('div');
    summarySection.className = 'change-summary-section';
    summarySection.innerHTML = `
      <h3 style="color:#109CF1;">Changes Summary</h3>
      <p class="date-range">Period: ${formatDate(start)} to ${formatDate(end)}</p>
    `;
    Object.entries(resourceGroups).forEach(([resource, changes]) => {
      if (changes.length === 0) return;
      const resourceTitle = document.createElement('div');
      resourceTitle.style.fontWeight = 'bold';
      resourceTitle.style.marginTop = '12px';
      resourceTitle.style.fontSize = '15px';
      resourceTitle.style.color = '#3b5998';
      resourceTitle.textContent = resource;
      const ul = document.createElement('ul');
      ul.style.margin = '5px 0 15px 15px';
      ul.style.padding = '0';
      changes.forEach(desc => {
        const li = document.createElement('li');
        li.textContent = desc;
        ul.appendChild(li);
      });
      summarySection.appendChild(resourceTitle);
      summarySection.appendChild(ul);
    });
    content.appendChild(summarySection);

    // --- 스타일 ---
    if (!document.getElementById('diff-popup-style')) {
      const style = document.createElement('style');
      style.id = 'diff-popup-style';
      style.textContent = `
        .change-summary-section {
          border-bottom: 2px solid #eee;
          margin-bottom: 20px;
          padding-bottom: 10px;
        }
        .change-summary-section h3 {
          color: #109CF1;
          margin: 0 0 5px 0;
          font-size: 20px;
        }
        .date-range {
          color: #334D6E;
          font-size: 14px;
          margin: 0 0 5px 0;
        }
        ul { margin-top:0; margin-bottom:0; }
        ul li { font-size:13px; color:#444; margin-bottom:2px; }
      `;
      document.head.appendChild(style);
    }
    popup.classList.remove('hidden');
  } catch (error) {
    console.error('Error showing diff:', error);
  }
}


function initializeChart() {
  const ctx = document.getElementById('scatterChart').getContext('2d');
  scatterChart = new Chart(ctx, {
    type: 'scatter',
    data: {
      datasets: []
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      layout: {
        padding: {
          top: 10,
          right: 20,
          bottom: 10,
          left: 20
        }
      },
      scales: {
        x: {
          type: 'time',
          time: {
            unit: 'hour',
            displayFormats: {
              hour: 'MMM d, HH:mm'
            }
          },
          title: {
            display: true,
            text: 'Time',
            font: { size: 14 }
          }
        },
        y: {
          type: 'category',
          labels: RESOURCE_TYPES,
          title: {
            display: true,
            text: 'Resource Type',
            font: { size: 14 }
          }
        }
      },
      plugins: {
        tooltip: {
          backgroundColor: 'rgba(255, 255, 255, 0.95)',
          titleColor: '#333',
          bodyColor: '#666',
          borderColor: '#ddd',
          borderWidth: 1,
          padding: 10,
          callbacks: {
            title: function(tooltipItems) {
              const item = tooltipItems[0];
              const date = new Date(item.parsed.x);
              return formatDate(date);
            },
            label: function(context) {
              const point = context.raw;
              const typeLabel = point.type === 'shadow' ? 'Shadow IT' : 
                              point.type === 'added' ? 'Addition' : 
                              'Removal';
              return [
                `Type: ${typeLabel}`,
                `Resource: ${point.resource}`,
                `Description: ${point.description}`
              ];
            }
          }
        },
        legend: {
          position: 'top',
          labels: {
            usePointStyle: true
          }
        }
      }
    }
  });
}
