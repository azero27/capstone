
import subprocess

def run_s3scanner(domain):
    """
    S3Scanner를 실행하여 주어진 IP에 대해 S3 버킷을 스캔하는 함수.
    
    Parameters:
    ip (str): 스캔할 IP 주소 또는 도메인
    
    Returns:
    dict: S3 버킷 스캔 결과를 포함한 딕셔너리
    """
    command = ["python3", "s3scanner.py", "--target", domain]
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode == 0:
        # 결과를 콘솔에 출력하고 후속 도구들에 반환
        print(f"S3Scanner result: {result.stdout}")
        return {
            "tool": "s3scanner",
            "output": result.stdout,
            "status": "success"
        }
    else:
        # 오류가 발생했을 경우
        print(f"S3Scanner error: {result.stderr}")
        return {
            "tool": "s3scanner",
            "output": result.stderr,
            "status": "error"
        }
