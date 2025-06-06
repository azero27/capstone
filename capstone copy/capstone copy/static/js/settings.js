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

// 파일 업로드 처리
async function handleFileUpload() {
    const domainFile = document.getElementById('domainFileInput').files[0];
    const portFile = document.getElementById('portFileInput').files[0];
    const s3File = document.getElementById('s3FileInput').files[0];

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

    // FormData 객체 생성
    const formData = new FormData();
    if (domainFile) formData.append('domain_file', domainFile);
    if (portFile) formData.append('port_file', portFile);
    if (s3File) formData.append('s3_file', s3File);

    try {
        const response = await fetch('/upload-data', {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const result = await response.json();
            alert(result.message);
            // 파일 입력 필드 초기화
            document.getElementById('domainFileInput').value = '';
            document.getElementById('portFileInput').value = '';
            document.getElementById('s3FileInput').value = '';
        } else {
            alert('파일 업로드에 실패했습니다.');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('파일 업로드 중 오류가 발생했습니다.');
    }
}

// 페이지 로드 시 현재 스캔 주기 가져오기
async function loadScanPeriod() {
    try {
        const response = await fetch('/get-scan-period');
        if (response.ok) {
            const data = await response.json();
            document.getElementById('scanPeriod').value = data.period.toString();
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

// 페이지 이동 함수들
function movetoSc() {
    window.location.href = '/';
}

function movetoRe() {
    window.location.href = '/report';
}

function movetoAr() {
    window.location.href = '/archiving';
}

// 사이드바 토글 함수
function toggleSidebar() {
    const sideBar = document.getElementById('sideBar');
    const toggleIcon = document.getElementById('toggleIcon');
    const container = document.querySelector('.container');
    
    if (sideBar.style.width === '78px' || sideBar.style.width === '') {
        sideBar.style.width = '256px';
        container.style.marginLeft = '256px';
        toggleIcon.src = toggleIcon.getAttribute('data-close-src');
    } else {
        sideBar.style.width = '78px';
        container.style.marginLeft = '78px';
        toggleIcon.src = toggleIcon.getAttribute('data-open-src');
    }
}

// 페이지 로드 시 실행
document.addEventListener('DOMContentLoaded', loadScanPeriod);