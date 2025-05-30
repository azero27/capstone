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

def run_nuclei_from_db(template_path: str, scan_result_id: int = None) -> dict:
    """
    DB의 DomainList 테이블에서 모든 도메인을 조회하여
    각 도메인에 대해 run_nuclei()를 호출하고, 결과 리스트를 반환합니다.

    Parameters:
    - template_path (str): Nuclei 템플릿 경로
    - scan_result_id (int, optional): 연관된 scan_result_id (결과 dict에 추가)

    Returns:
    - List[dict]: 각 도메인 스캔 결과의 dict 리스트
    """
    # 1) MySQL에서 도메인 목록 조회
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
        # 연결 또는 쿼리 오류 처리
        print(f"[ERROR] 도메인 목록 조회 실패: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    # 2) 각 도메인에 대해 Nuclei 스캔 실행
    results = []
    for domain in domains:
        res = run_nuclei(domain, template_path)
        if scan_result_id is not None:
            res["scan_result_id"] = scan_result_id
        results.append(res)

    return results