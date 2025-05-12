import subprocess
import re

def run_nmap(ip):
    """
    Nmap 스캔을 실행하고, 포트, 서비스 버전, 운영체제 정보를 추출하는 함수.
    
    Parameters:
    ip (str): 스캔할 IP 주소
    
    Returns:
    dict: 스캔 결과를 포함한 딕셔너리
    """
    command = ["nmap", "-sV", ip]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Nmap 출력에서 포트, 서비스, 운영체제 정보 추출
        open_ports = extract_open_ports(result.stdout)
        service_info = extract_service_info(result.stdout)
        
        
        # 결과가 비어있다면 기본 값 설정 (없을 경우 '정보 없음' 처리)
        if not open_ports:
            open_ports = "No open ports found"
        if not service_info:
            service_info = "No service information found"
        
        return {
            "tool": "nmap",
            "output": result.stdout,
            "open_ports": open_ports,  # 열린 포트 정보
            "service_info": service_info,  # 서비스 정보
            "status": "success"
        }
    else:
        return {
            "tool": "nmap",
            "output": result.stderr,
            "status": "error"
        }

def extract_open_ports(nmap_output):
    """
    Nmap 출력에서 열린 포트 정보를 추출하는 함수.
    예시 출력: 22/tcp open  ssh OpenSSH 7.9p1
    """
    ports = []
    lines = nmap_output.splitlines()
    for line in lines:
        if "/tcp" in line and "open" in line:  # 서비스 포트가 열려있는 경우
            port_info = line.split()
            port = port_info[0]
            ports.append(port)
    return ports

def extract_service_info(nmap_output):
    """
    Nmap 출력에서 서비스 정보 추출하는 함수.
    예시 출력: 22/tcp open  ssh OpenSSH 7.9p1
    """
    services = []
    lines = nmap_output.splitlines()
    for line in lines:
        if "/tcp" in line and "open" in line:  # 서비스 포트가 열려있는 경우
            parts = line.split()
            port = parts[0]
            service = parts[2]
            version = " ".join(parts[3:])
            services.append({
                "port": port,
                "service": service,
                "version": version
            })
    return services

