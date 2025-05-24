import subprocess
import datetime

def run_amass(keyword: str):
    """
    키워드를 받아 keyword.com 도메인을 대상으로 amass 실행
    """
    domain = f"{keyword}.com"
    start_time = datetime.datetime.now()
    command = ["amass", "enum", "-passive", "-d", domain]

    result = subprocess.run(command, capture_output=True, text=True)
    end_time = datetime.datetime.now()

    return {
        "tool": "amass",
        "target_url": domain,
        "command": " ".join(command),
        "output": result.stdout,
        "output_log": result.stdout + "\n" + result.stderr,
        "success": 1 if result.returncode == 0 else 0,
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "status": "success" if result.returncode == 0 else "error"
    }
