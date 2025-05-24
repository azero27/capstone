import os
import subprocess
from datetime import datetime

def run_cloud_enum(keyword):
    cloud_enum_path = os.path.expanduser("~/cloud-1/capstone/capstone/tools/cloud_enum/cloud_enum.py")
    command = ["python3", cloud_enum_path, "-k", keyword]

    start_time = datetime.now()
    log_dir = os.path.expanduser("~/cloud-1/capstone/capstone/logs")
    os.makedirs(log_dir, exist_ok=True)

    timestamp = start_time.strftime("%Y%m%d_%H%M%S_%f")
    log_path = os.path.join(log_dir, f"cloud_enum_{timestamp}.log")

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        with open(log_path, "w", encoding="utf-8") as logfile:
            for line in iter(process.stdout.readline, ''):
                print("[LOG]", line.strip())
                logfile.write(line)
        process.stdout.close()
        process.wait()

        end_time = datetime.now()

        if process.returncode != 0:
            print(f"[ERROR] cloud_enum 종료 코드: {process.returncode}")

        return {
            "status": "success" if process.returncode == 0 else "error",
            "output_file": log_path,
            "command": " ".join(command),
            "start_time": start_time,
            "end_time": end_time
        }

    except Exception as e:
        print(f"[ERROR] cloud_enum 실행 중 예외 발생: {e}")
        return {
            "status": "error",
            "output_file": log_path,
            "command": " ".join(command),
            "start_time": start_time,
            "end_time": datetime.now()
        }
