let globalStopFlag = false;
let globalExitFlag = false;
function toggleSidebar() {
  const sideBar = document.getElementById('sideBar');
  const container = document.querySelector('.container');
  const icon = document.getElementById('toggleIcon');
  const sidebarTexts = document.querySelectorAll('.sidebar-text');
  const archivingSubmenu = document.getElementById('archivingSubmenu');

  const isCollapsed = sideBar.style.width === '68px' || !sideBar.style.width;

  if (isCollapsed) {
    // 사이드바 확장
    sideBar.style.width = '256px';
    container.style.marginLeft = '256px';
    icon.src = icon.dataset.openSrc;

    sidebarTexts.forEach(el => {
      el.style.display = 'block';
    });

    if (archivingSubmenu && isArchivingVisible) {
      archivingSubmenu.style.display = 'block';
    }

  } else {
    // 사이드바 축소
    sideBar.style.width = '68px';
    container.style.marginLeft = '68px';
    icon.src = icon.dataset.closeSrc;

    sidebarTexts.forEach(el => {
      el.style.display = 'none';
    });

    if (archivingSubmenu) {
      archivingSubmenu.style.display = 'none';
    }
  }
}


function handleStop() {
  globalStopFlag = true;
  console.log("STOP 클릭됨, stopFlag =", globalStopFlag);
  alert("스캔 중지 요청됨.");
}

function handleExit() {
  globalExitFlag = true;
  console.log("EXIT 클릭됨, exitFlag =", globalExitFlag);
  alert("프로그램 종료 요청됨.");
}

let isArchivingVisible = false;

function toggleArchivingSubmenu() {
  const submenu = document.getElementById("archivingSubmenu");
  const tasks = document.querySelector('.tasks2');
  const submenuItems = document.querySelectorAll('.submenu-item');
  const isVisible = submenu.style.display === "block";

  // 서브메뉴 표시/숨기기
  submenu.style.display = isVisible ? "none" : "block";
  
  if (!isVisible) {
    // 서브메뉴가 열리면, tasks2와 나머지 항목의 위치를 재정렬
    document.querySelector('.settings2').style.top = "440px";
    document.querySelector('.email2').style.top = "229px";
    document.querySelector('.icon-menu-email').style.top = "229px";
    document.querySelector('.dashboard2').style.top = "-146px";
    
    isArchivingVisible = true;
  } else {
    // 서브메뉴가 닫히면, 원래대로 복원
    tasks.style.top = "109px"; // 원래 위치로 복원
    document.querySelector('.settings2').style.top = "440px";
    document.querySelector('.email2').style.top = "149px"; // 원래 위치로 복원
    document.querySelector('.icon-menu-email').style.top = "149px";
    document.querySelector('.dashboard2').style.top = "69px"; // 원래 위치로 복원
    

    isArchivingVisible = false;
  }
}


// 이동 함수들 (Flask 라우팅 기준 URL 구성)
function movetoRe() {
  window.location.href = "/report";
}

function movetoSc() {
  window.location.href = "/scan-page";
}

function movetoTl() {
  window.location.href = "/archiving/timeline";
}

function movetoSn() {
  window.location.href = "/archiving/snapshot";
}

function movetoAr() {
  window.location.href = "/archiving/timeline";
}

function movetoSet() {
  window.location.href = "/settings";
}

// 스캔 상세 결과 이동
function movetoSn_s(id) {
  console.log("SCAN view 이동 - ID:", id);
  window.location.href = `/archiving/snapshot/scan/` + id;
}

function movetoSn_i(id) {
  console.log("INFO view 이동 - ID:", id);
  window.location.href = `/archiving/snapshot/info/` + id;
}