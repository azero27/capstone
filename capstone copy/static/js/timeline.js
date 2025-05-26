let selectedDates = [];
let viewstart = null;
let viewend = null;
let diffstart = null;
let diffend = null;

const timelineData = [
  { date: "2025-05-01T10:00", rsc: "server1", dif: "port 80 opened" },
  { date: "2025-05-02T12:30", rsc: "server2", dif: "new user added" },
  { date: "2025-05-04T09:15", rsc: "server1", dif: "config change" },
  { date: "2025-05-05T14:00", rsc: "server3", dif: "SSH disabled" },
  { date: "2025-05-05T16:00", rsc: "server1", dif: "SSH disabled" },
];

function renderTimeline() {
  const container = document.getElementById("timelineList");
  container.innerHTML = "";

  filteredTimelineData.forEach((entry, index) => {
    const item = document.createElement("div");
    item.className = "timeline-item";

    const dot = document.createElement("div");
    dot.className = "timeline-dot";
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

function toggleSelectDot(date, dotEl) {
  if (selectedDates.length === 2) {
    selectedDates = [];
    document.querySelectorAll('.timeline-dot').forEach(dot => dot.classList.remove('selected'));
  }

  selectedDates.push(date);
  dotEl.classList.add("selected");

  if (selectedDates.length === 2) {
    selectedDates.sort();
    diffstart = selectedDates[0];
    diffend = selectedDates[1];
    renderDiffs();
  }
}

function renderDiffs() {
  const diffContainer = document.getElementById("diffList");
  diffContainer.innerHTML = "";

  const filtered = timelineData.filter(entry => entry.date >= diffstart && entry.date <= diffend);
  filtered.forEach(entry => {
    const div = document.createElement("div");
    div.className = "diff-entry";
    div.innerHTML = `Diff(<span class="resource" onclick="showPopup('${entry.rsc}')">${entry.rsc}</span>, ${entry.dif})`;
    diffContainer.appendChild(div);
  });
}

function showPopup(rsc) {
  const popup = document.getElementById("popup");
  const popupContent = document.getElementById("popupContent");
  popup.classList.remove("hidden");

  const filtered = timelineData.filter(e => e.rsc === rsc && e.date >= diffstart && e.date <= diffend);
  popupContent.innerHTML = filtered.map(e => `<div>${formatDate(e.date)} - ${e.dif}</div>`).join("");
}

function closePopup() {
  document.getElementById("popup").classList.add("hidden");
}

function applyViewFilter() {
  viewstart = document.getElementById("viewStart").value;
  viewend = document.getElementById("viewEnd").value;

  if (!viewstart || !viewend) {
    filteredTimelineData = [...timelineData];
  } else {
    filteredTimelineData = timelineData.filter(entry => {
      return entry.date >= viewstart && entry.date <= viewend;
    });
  }

  selectedDates = []; // 선택 초기화
  diffstart = null;
  diffend = null;
  renderTimeline(); // 필터된 데이터로 다시 렌더링
  document.getElementById("diffList").innerHTML = ""; // Diff View 초기화
}

document.addEventListener("DOMContentLoaded", renderTimeline);
