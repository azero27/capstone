// 예시: DB에서 받아온 현재 선택된 클라우드 정보
const currentCloud = {
  id: 1,
  type: "AWS",
  ip: "",
  domain: "example.com"
};

window.onload = () => {
  const parts = [];
  if (currentCloud.domain) parts.push(`도메인: ${currentCloud.domain}`);
  if (currentCloud.ip) parts.push(`IP: ${currentCloud.ip}`);
  if (currentCloud.type) parts.push(`유형: ${currentCloud.type}`);

  document.getElementById('cloudInfoText').innerText = parts.join(" / ") || "클라우드 정보 없음";

  // 기본값을 선택된 항목으로 (선택되어 있음: 2시간)
  document.getElementById('scanPeriod').value = "2";
};

function saveScanPeriod() {
  const selectedHours = parseInt(document.getElementById('scanPeriod').value);

  if (isNaN(selectedHours) || selectedHours < 1) {
    alert("1시간 이상의 유효한 값을 선택하세요.");
    return;
  }

  fetch('/set-schedule', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      interval_seconds: selectedHours * 3600
    })
  })
  .then(res => res.json())
  .then(data => {
    if (data.status === "ok") {
      alert("스캔 주기가 저장되었습니다.");
    } else {
      alert(data.message || "저장 실패");
    }
  })
  .catch(() => {
    alert("저장 중 오류가 발생했습니다.");
  });
}