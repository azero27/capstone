document.addEventListener("DOMContentLoaded", async () => {
  // 리소스 목록을 API에서 받아와 렌더
  const res = await fetch("/api/resources");
  const fetchedResources = await res.json();

  const container = document.getElementById("resourceCheckboxes");
  container.innerHTML = '';

  fetchedResources.forEach(resource => {
    const div = document.createElement("div");
    div.innerHTML = `
      <label>
        <input type="checkbox" name="resourceType" value="${resource}"> ${resource}
      </label>
    `;
    container.appendChild(div);
  });
});

async function generateReport() {
  const startDate = document.getElementById("startDate").value;
  const endDate = document.getElementById("endDate").value;
  const checkboxes = document.querySelectorAll('input[name="resourceType"]:checked');
  const selectedResources = Array.from(checkboxes).map(cb => cb.value);

  // 유효성 검사
  if (!startDate || !endDate) {
    alert("시작일과 종료일을 모두 선택해주세요.");
    return;
  }
  if (startDate > endDate) {
    alert("시작일은 종료일보다 이전이어야 합니다.");
    return;
  }
  if (selectedResources.length === 0) {
    alert("하나 이상의 리소스를 선택해주세요.");
    return;
  }

  // API로 보고서 생성 요청
  try {
    const res = await fetch("/api/generate_report", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        start_date: startDate,
        end_date: endDate,
        resources: selectedResources
      })
    });

    const data = await res.json();
    const resultDiv = document.getElementById("reportResult");

    if (data.status === "ok") {
      resultDiv.innerHTML = `
        <h4>선택된 필터</h4>
        <p><strong>기간:</strong> ${startDate} ~ ${endDate}</p>
        <p><strong>리소스:</strong> ${selectedResources.join(", ")}</p>
        <a href="${data.pdf_url}" download class="download-link">PDF 다운로드</a>
      `;
    } else {
      resultDiv.innerHTML = `<p style="color:red;">${data.message || "보고서 생성 실패"}</p>`;
    }
  } catch (err) {
    alert("보고서 생성 중 오류가 발생했습니다.");
  }
}
