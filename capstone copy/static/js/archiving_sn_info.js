function getScanIdFromUrl() {
  const match = window.location.pathname.match(/(\d+)/);
  return match ? parseInt(match[1], 10) : 1;
}

document.addEventListener("DOMContentLoaded", async () => {
  // 스냅샷 id는 URL이나 글로벌 변수에서 추출 필요 (예시로 1 사용)
  const scanId = getScanIdFromUrl(); // URL에서 추출 추천

  const res = await fetch(`/api/snapshots/${scanId}/resources`);
  const resourceList = await res.json();

  const container = document.getElementById("resourceCheckboxes");

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
});

function updateSelected() {
  const checkboxes = document.querySelectorAll('input[name="resourceType"]:checked');
  const selected = Array.from(checkboxes).map(cb => cb.value);

  const box = document.getElementById("selectedResources");
  box.innerHTML = selected.length ? selected.join(', ') : "선택된 리소스 없음";
}
