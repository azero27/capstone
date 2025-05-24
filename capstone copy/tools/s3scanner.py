def run_s3scanner():
    from datetime import datetime
    import subprocess
    import os

    s3scanner_path = os.path.join(
        os.path.expanduser("~"),
        "cloud-1", "capstone", "capstone", "tools", "S3Scanner", "s3scanner"
    )

    bucket_list = os.path.join(
        os.path.expanduser("~"),
        "cloud-1", "capstone", "capstone", "tools", "S3Scanner", "names.txt"
    )

    command = [s3scanner_path, "-bucket-file", bucket_list, "-enumerate"]
    # command = [s3scanner_path, "-bucket", bucket_name, "-enumerate"]
    start_time = datetime.now()

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    full_output = ""
    for line in process.stdout:
        print("[LOG]", line.strip())  # 실시간 출력
        full_output += line
    process.stdout.close()
    process.wait()  # 출력 완료 보장

    end_time = datetime.now()

    return {
        "tool": "s3scanner",
        "output": full_output,
        "status": "success" if process.returncode == 0 else "error",
        "start_time": start_time,
        "end_time": end_time,
        "command": " ".join(command)
    }