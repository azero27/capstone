async function handleScan() {
  const selectedType = document.querySelector('input[name="targetType"]:checked').value;
  const ipInput = document.getElementById("ipInput").value.trim();
  const domainInput = document.getElementById("domainInput").value.trim();
  const fileInput = document.getElementById("resourceFile");
  const file = fileInput.files[0];

  let value = '';
  if (selectedType === 'domain') {
    if (!domainInput) {
      alert("도메인을 입력하세요.");
      return;
    }
    value = domainInput;
  } else {
    if (!ipInput) {
      alert("IP를 입력하세요.");
      return;
    }
    value = ipInput;
  }

  // 정보 localStorage 저장 (scan.js에서 활용)
  localStorage.setItem('resource_type', selectedType);
  localStorage.setItem('target_value', value);

  // (선택) 리소스 파일 업로드
  if (file) {
    try {
      await uploadResourceFile(file);
    } catch (e) {
      alert("파일 업로드 실패: " + e.message);
      return;
    }
  }

  // 백엔드에 scan POST 요청
  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        resource_type: selectedType,
        value: value
      })
    });
    if (!res.ok) throw new Error("스캔 요청 실패");
    // 성공 시 scan 페이지로 이동
    window.location.href = '/scan-page';
  } catch (error) {
    alert(error.message);
  }
}

async function uploadResourceFile(file) {
  const formData = new FormData();
  formData.append('resourceFile', file);

  const response = await fetch('/api/uploadResourceFile', {
    method: 'POST',
    body: formData
  });

  if (!response.ok) {
    throw new Error('리소스 파일 업로드 실패');
  }
  return await response.json();
}
