import subprocess

def run_cloud_enum(ip):
    """
    Cloud-Enum을 실행하여 주어진 IP에 대해 클라우드 자원을 스캔하는 함수.
    
    Parameters:
    ip (str): 분석할 IP 주소
    
    Returns:
    dict: Cloud-Enum 결과를 포함한 딕셔너리
    """
    command = ["cloud_enum", "--ip", ip]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        return {
            "tool": "cloud_enum",
            "output": result.stdout,
            "status": "success"
        }
    else:
        return {
            "tool": "cloud_enum",
            "output": result.stderr,
            "status": "error"
        }
