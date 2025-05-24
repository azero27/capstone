# tools/nuclei.py

import subprocess
import datetime

def run_nuclei(url: str, template_path: str):
    """
    Parameters:
    - url (str): 탐지 대상 URL
    - template_path (str): Nuclei 템플릿 경로

    Returns:
    - dict: 실행 결과 및 메타 정보 포함
    """
    start_time = datetime.datetime.now()

    command = ["nuclei", "-u", url, "-t", template_path, "-stats"]
    result = subprocess.run(command, capture_output=True, text=True)
    
    end_time = datetime.datetime.now()

    full_output = result.stdout.strip() + "\n" + result.stderr.strip()
    scan_success = "Templates loaded" in result.stderr or "Started scanning" in result.stderr

    return {
        "tool": "nuclei",
        "target_url": url,
        "template": template_path,
        "output": result.stdout,
        "output_log": full_output.strip(),
        "command": " ".join(command),
        "success": int(result.returncode == 0 and scan_success),
        "start_time": start_time.isoformat(),
        "end_time": end_time.isoformat(),
        "status": "success" if result.returncode == 0 and scan_success else "error"
    }
