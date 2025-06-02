let selectedDates = [];
let viewstart = null;
let viewend = null;
let diffstart = null;
let diffend = null;
let filteredTimelineData = [];

// ========== API 호출 함수 ==========
async function loadTimelineNodes(start, end) {
  const res = await fetch('/api/timeline_nodes', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ start, end })
  });
  return res.json();
}

async function loadTimelineDiff(start, end) {
  const res = await fetch('/api/timeline_diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ start, end })
  });
  return res.json();
}

async function loadResourceDiff(resource, start, end) {
  const res = await fetch('/api/resource_diff', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ resource, start, end })
  });
  return res.json();
}

// ========== 렌더링 함수 ==========
async function renderTimeline() {
  const container = document.getElementById("timelineList");
  container.innerHTML = "";

  // 기간값 없으면 전체 범위 지정 (또는 기본값)
  let start = viewstart || "1900-01-01T00:00";
  let end = viewend || "2999-12-31T23:59";

  // 데이터 API로 받아오기
  filteredTimelineData = await loadTimelineNodes(start, end);

  filteredTimelineData.forEach((entry, index) => {
    const item = document.createElement("div");
    item.className = "timeline-item";

    const dot = document.createElement("div");
    dot.className = "timeline-dot";
    // 선택된 경우 표시
    if (selectedDates.includes(entry.date)) dot.classList.add("selected");
    dot.onclick = () => toggleSelectDot(entry.date, dot);

    const line = document.createElement("div");
    line.className = "timeline-line";

    const text = document.createElement("div");
    text.innerHTML = `${formatDate(entry.date)} Diff(${entry.rsc}, ${entry.dif})`;

    item.appendChild(dot);
    if (index < filteredTimelineData.length - 1) item.appendChild(line);
    item.appendChild(text);

    container.appendChild(item);
  });
}

function formatDate(dtStr) {
  const d = new Date(dtStr);
  const date = `${d.getDate().toString().padStart(2, '0')}-${(d.getMonth() + 1).toString().padStart(2, '0')}-${d.getFullYear()}`;
  const time = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
  return `${date} ${time}`;
}

// ========== Dot 선택 및 Diff 렌더 ==========
async function toggleSelectDot(date, dotEl) {
  // 두 개 선택 시 초기화
  if (selectedDates.length === 2) {
    selectedDates = [];
    document.querySelectorAll('.timeline-dot').forEach(dot => dot.classList.remove('selected'));
  }
  // 이미 선택된 경우 무시
  if (selectedDates.includes(date)) return;

  selectedDates.push(date);
  dotEl.classList.add("selected");

  if (selectedDates.length === 2) {
    selectedDates.sort(); // 시간순
    diffstart = selectedDates[0];
    diffend = selectedDates[1];
    await renderDiffs();
  }
}

async function renderDiffs() {
  const diffContainer = document.getElementById("diffList");
  diffContainer.innerHTML = "";

  // diff는 반드시 API 통해
  const diffEntries = await loadTimelineDiff(diffstart, diffend);

  diffEntries.forEach(entry => {
    const div = document.createElement("div");
    div.className = "diff-entry";
    div.innerHTML =
      `Diff(<span class="resource" onclick="showPopup('${entry.rsc}')">${entry.rsc}</span>, ${entry.dif})`;
    diffContainer.appendChild(div);
  });
}

// ========== 리소스 변화 상세 팝업 ==========
async function showPopup(rsc) {
  const popup = document.getElementById("popup");
  const popupContent = document.getElementById("popupContent");
  popup.classList.remove("hidden");

  // 리소스별 변화 API 호출
  const resourceDiffs = await loadResourceDiff(rsc, diffstart, diffend);
  popupContent.innerHTML = resourceDiffs
    .map(e => `<div>${formatDate(e.date)} - ${e.dif}</div>`)
    .join("");
}

function closePopup() {
  document.getElementById("popup").classList.add("hidden");
}

// ========== 기간 필터 적용 ==========
async function applyViewFilter() {
  viewstart = document.getElementById("viewStart").value;
  viewend = document.getElementById("viewEnd").value;

  // 선택/차이 초기화
  selectedDates = [];
  diffstart = null;
  diffend = null;

  await renderTimeline();
  document.getElementById("diffList").innerHTML = "";
}

// ========== 초기화 ==========
document.addEventListener("DOMContentLoaded", () => {
  renderTimeline();
});
