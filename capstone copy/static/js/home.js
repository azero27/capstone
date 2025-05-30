async function handleScan() {
  const selectedType = document.querySelector('input[name="targetType"]:checked').value;
  const ipInput = document.getElementById("ipInput").value.trim();
  const domainInput = document.getElementById("domainInput").value.trim();

  // 파일 인풋 (3개)
  const domainFileInput = document.getElementById("domainFileInput");
  const portFileInput = document.getElementById("portFileInput");
  const s3FileInput = document.getElementById("s3FileInput");

  const domainFile = domainFileInput.files[0];
  const portFile = portFileInput.files[0];
  const s3File = s3FileInput.files[0];

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

  // 파일명 검사
  if (domainFile && domainFile.name !== "domain.csv") {
    alert("Domain 파일의 이름은 반드시 domain.csv여야 합니다.");
    return;
  }
  if (portFile && portFile.name !== "port.csv") {
    alert("Port 파일의 이름은 반드시 port.csv여야 합니다.");
    return;
  }
  if (s3File && s3File.name !== "s3.csv") {
    alert("S3 파일의 이름은 반드시 s3.csv여야 합니다.");
    return;
  }

  // 정보 localStorage 저장 (scan.js에서 활용)
  localStorage.setItem('resource_type', selectedType);
  localStorage.setItem('target_value', value);

  // (선택) 리소스 파일 업로드 (셋 중 하나라도 있으면 요청)
  if (domainFile || portFile || s3File) {
    try {
      await uploadResourceFiles(domainFile, portFile, s3File);
      alert("리소스 파일이 성공적으로 업로드되었습니다.");
    } catch (e) {
      alert("파일 업로드 실패: " + e.message);
      return;
    }
  }

  // 이후 추가 동작(예: 스캔 시작 API 등)이 있다면 여기에 이어서 작성
  // 예시: /submit 호출 등
  try {
    const formData = new FormData();
    formData.append('ip_address', selectedType === 'ip' ? value : '');
    formData.append('domain', selectedType === 'domain' ? value : '');

    const res = await fetch('/submit', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (!res.ok || data.status !== 'scheduled') {
      throw new Error(data.message || "스캔 요청 실패");
    }
    window.location.href = '/scan-page';

  }
}

// 3개의 파일을 동시에 업로드
async function uploadResourceFiles(domainFile, portFile, s3File) {
  const formData = new FormData();
  if (domainFile) formData.append('domain_file', domainFile);
  if (portFile) formData.append('port_file', portFile);
  if (s3File) formData.append('s3_file', s3File);

  const response = await fetch('/upload-data', {
    method: 'POST',
    body: formData
  });

  const data = await response.json();
  if (!response.ok || data.status !== 'ok') {
    throw new Error('리소스 파일 업로드 실패: ' + (data.message || ''));
  }
  return data.message || '업로드 성공';
}
