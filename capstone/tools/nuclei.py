import subprocess

def run_nuclei(url):
    """
    
    Parameters:
    ip (str): 분석할 IP 주소
    
    Returns:
    dict: Nuclei 결과를 포함한 딕셔너리
    """
    command = ["nuclei", "-u", url]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        return {
            "tool": "nuclei",
            "output": result.stdout,
            "status": "success"
        }
    else:
        return {
            "tool": "nuclei",
            "output": result.stderr,
            "status": "error"
        }
