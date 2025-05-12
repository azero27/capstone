import subprocess

def run_amass(domain):
    """
    Amass를 실행하여 도메인에 대한 서브도메인을 수집하는 함수.
    
    Parameters:
    domain (str): 분석할 도메인 이름
    
    Returns:
    dict: 서브도메인 수집 결과를 포함한 딕셔너리
    """
    command = ["amass", "enum", "-d", domain]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        # 결과를 콘솔에 출력하고 후속 도구들에 반환
        print(f"Amass result: {result.stdout}")
        subdomains = extract_subdomains(result.stdout)
        return {
            "tool": "amass",
            "output": result.stdout,
            "subdomains": subdomains,  # 서브도메인 정보
            "status": "success"
        }
    else:
        # 오류가 발생했을 경우
        print(f"Amass error: {result.stderr}")
        return {
            "tool": "amass",
            "output": result.stderr,
            "status": "error"
        }

def extract_subdomains(amass_output):
    """
    Amass 출력에서 서브도메인 정보를 추출하는 함수.
    """
    subdomains = []
    lines = amass_output.splitlines()
    for line in lines:
        if line and "?" not in line:  # 서브도메인 정보만 추출
            subdomains.append(line.strip())  # 서브도메인 목록을 저장
    return subdomains
