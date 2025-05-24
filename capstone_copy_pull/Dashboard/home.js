let IPorDomain = '';

function handleScan() {
  const input = document.getElementById("ipInput").value.trim();
  if (input === '') {
    alert("IP 또는 도메인을 입력해주세요.");
    return;
  }

  IPorDomain = input;
  console.log("입력값 저장됨:", IPorDomain);
  scan(IPorDomain);
}

function scan(ip) {
  console.log("스캔 시작:", ip);
  IPorDomain = ip;
  alert("스캔 대상 IP: " + ip);
  localStorage.setItem('targetIP', ip);
  window.location.href = 'scan.html';
}