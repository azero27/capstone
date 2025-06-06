// URL에서 scanId 추출
function getScanIdFromUrl() {
  const match = window.location.pathname.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : 1;
}

// 전역 상태
let currentResourceMap = {};   // { S3: [bucket1, bucket2], ... }
let currentSelectedTypes = []; // ["S3", "EBS", ...]

// 리소스 체크박스 렌더링
function renderResourceCheckboxes(resourceMap) {
  const container = document.getElementById("resourceCheckboxes");
  container.innerHTML = '';

  // resourceMap: { S3: [...], EBS: [...], ... }
  Object.keys(resourceMap).forEach(resourceType => {
    const wrapper = document.createElement("div");
    wrapper.classList.add("checkbox-wrapper");
    wrapper.innerHTML = `
      <label>
        <input type="checkbox" name="resourceType" value="${resourceType}" onchange="updateSelected()"> ${resourceType}
      </label>
    `;
    container.appendChild(wrapper);
  });
}

// Shadow IT 필터 체크박스에 따라 리소스 목록 불러오기
async function filterResourceList() {
  const scanId = getScanIdFromUrl();
  const shadowOnly = document.getElementById("shadowOnlyCheckbox").checked;
  let resourceMap = {};
  try {
    let url = shadowOnly
      ? `/api/snapshots/${scanId}/shadow_resources`
      : `/api/snapshots/${scanId}/resources`;

    const res = await fetch(url);
    resourceMap = await res.json(); // { S3: [bucket1, ...], EBS: [...] }
  } catch (e) {
    resourceMap = {};
    alert("리소스 목록을 불러오지 못했습니다.");
  }
  currentResourceMap = resourceMap;
  renderResourceCheckboxes(resourceMap);
  updateSelected(); // 선택 표시 갱신
}

// 선택된 리소스 목록/세부 표시
function updateSelected() {
  const checkboxes = document.querySelectorAll('input[name="resourceType"]:checked');
  const selected = Array.from(checkboxes).map(cb => cb.value);

  const box = document.getElementById("selectedResources");
  if (selected.length === 0) {
    box.innerHTML = "선택된 리소스 없음";
    document.getElementById("resourceDetails").innerHTML = "리소스 세부 정보 표시 영역";
    return;
  }

  // 상단: 선택된 종류 나열
  box.innerHTML = selected.join(', ');

  // 세부 정보(아래): 각 종류별 실제 항목들
  let detailHtml = "";
  selected.forEach(type => {
    const items = currentResourceMap[type] || [];
    detailHtml += `<b>${type}:</b> `;
    if (items.length === 0) {
      detailHtml += "<i>해당 리소스 없음</i><br>";
    } else {
      detailHtml += items.map(x => `<span style="margin-right:8px">${x}</span>`).join(', ') + "<br>";
    }
  });
  document.getElementById("resourceDetails").innerHTML = detailHtml;
}

// 최초 로드 시 자동 실행
document.addEventListener("DOMContentLoaded", filterResourceList);
