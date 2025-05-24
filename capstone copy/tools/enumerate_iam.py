import subprocess
import os
from datetime import datetime

def run_enumerate_iam(access_key, secret_key):
    enumerate_iam_path = os.path.expanduser("~/cloud-1/capstone/capstone/tools/enumerate-iam/enumerate-iam.py")
    command = ["python3", enumerate_iam_path, "--access-key", access_key, "--secret-key", secret_key]

    start_time = datetime.now()
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    # 로그 저장 경로 설정
    log_dir = os.path.expanduser("~/cloud-1/capstone/capstone/logs")
    os.makedirs(log_dir, exist_ok=True)

    # microseconds 포함한 timestamp로 충돌 방지
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    log_path = os.path.join(log_dir, f"enumerate_iam_{timestamp}.log")

    # 실시간으로 로그 저장 + 콘솔 출력
    with open(log_path, "w", encoding="utf-8") as logfile:
        for line in iter(process.stdout.readline, ''):
            print("[LOG]", line.strip())  # 디버깅용 콘솔 출력
            logfile.write(line)
    process.stdout.close()
    process.wait()
    end_time = datetime.now()

    return {
        "status": "success" if process.returncode == 0 else "error",
        "output_file": log_path,  # 파일 경로 반환
        "command": " ".join(command),
        "start_time": start_time,
        "end_time": end_time
    }
