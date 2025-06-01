// URL에서 scanId 추출
function getScanIdFromUrl() {
  const match = window.location.pathname.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : 1;
}

// 상태 변수
let currentResourceList = [];

// 리소스 체크박스 렌더링
function renderResourceCheckboxes(resourceList) {
  const container = document.getElementById("resourceCheckboxes");
  container.innerHTML = '';

  resourceList.forEach(resource => {
    const wrapper = document.createElement("div");
    wrapper.classList.add("checkbox-wrapper");
    wrapper.innerHTML = `
      <label>
        <input type="checkbox" name="resourceType" value="${resource}" onchange="updateSelected()"> ${resource}
      </label>
    `;
    container.appendChild(wrapper);
  });
}

// Shadow IT 필터 체크박스에 따라 리소스 목록 불러오기
async function filterResourceList() {
  const scanId = getScanIdFromUrl();
  const shadowOnly = document.getElementById("shadowOnlyCheckbox").checked;
  let resourceList = [];
  try {
    let url = shadowOnly
      ? `/api/snapshots/${scanId}/shadow_resources`
      : `/api/snapshots/${scanId}/resources`;

    const res = await fetch(url);
    resourceList = await res.json();
  } catch (e) {
    resourceList = [];
    alert("리소스 목록을 불러오지 못했습니다.");
  }
  currentResourceList = resourceList;
  renderResourceCheckboxes(resourceList);
  updateSelected(); // 선택 표시 갱신
}

// 선택된 리소스 목록 표시
function updateSelected() {
  const checkboxes = document.querySelectorAll('input[name="resourceType"]:checked');
  const selected = Array.from(checkboxes).map(cb => cb.value);

  const box = document.getElementById("selectedResources");
  box.innerHTML = selected.length ? selected.join(', ') : "선택된 리소스 없음";
}

// 최초 로드 시 자동 실행
document.addEventListener("DOMContentLoaded", filterResourceList);
