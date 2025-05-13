import subprocess
import os
from flask import Flask

def run_cloud_enum(keyword):


    # 현재 파일이 있는 디렉토리 (tools 디렉토리)
    current_dir = os.path.dirname(os.path.abspath(__file__))

    # 'capstone' 디렉토리로 올라가서 'home' 디렉토리로 이동
    home_dir = os.path.abspath(os.path.join(current_dir, '../../..'))

    # home 디렉토리 기준으로 상대 경로로 파일 열기
    cloud_enum_file_path = os.path.join(home_dir, 'cloud_enum', 'cloud_enum.py')

    command = ["cloud_enum_file_path", "-k", keyword]
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

