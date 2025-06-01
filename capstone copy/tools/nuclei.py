# tools/nuclei.py

import subprocess
import datetime
import mysql.connector 

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
    print(f"nuclei csv로 실행 성공?!")
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

    
def run_nuclei_from_db(template_path: str) -> dict:
    """
    DB의 DomainList 테이블에서 모든 도메인을 조회하여
    각 도메인에 대해 run_nuclei()를 호출하고, 전체 결과를 포함한 단일 dict 반환.

    Returns:
    - dict: 전체 실행 요약 및 결과 리스트 포함
    """
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE",
            port=3306
        )
        cursor = conn.cursor()
        cursor.execute("SELECT domain FROM DomainList")
        domains = [row[0] for row in cursor.fetchall()]
    except mysql.connector.Error as e:
        print(f"[ERROR] 도메인 목록 조회 실패: {e}")
        return {
            "status": "error",
            "message": str(e),
            "results": []
        }
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # Nuclei 실행
    print(f"nuclei 스캔 시작")
    results = []
    for domain in domains:
        res = run_nuclei(domain, template_path)
        results.append(res)

    return {
        "tool": "nuclei",
        "target_count": len(domains),
        "status": "success",
        "results": results,  # 여기에 전체 list를 포함
        "start_time": results[0]["start_time"] if results else None,
        "end_time": results[-1]["end_time"] if results else None,
        "output": "\n".join(r["output"] for r in results),  # 출력 모음
        "command": f"nuclei -u [multiple] -t {template_path}",
    }