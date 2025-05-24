import mysql.connector
from datetime import datetime

def save_nuclei_result(parsed_result, scan_result_id, step):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO NucleiResult (
            tool_id, scan_result_id, step, target, command, success,
            vulnerability, risk_level, url, log, start_time, end_time
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        parsed_result["tool_id"],
        scan_result_id,
        step,
        parsed_result["target"],
        parsed_result["command"],
        parsed_result["success"],
        parsed_result["vulnerability"],
        parsed_result["risk_level"],
        parsed_result["url"],
        parsed_result["log"],
        parsed_result["start_time"],
        parsed_result["end_time"]
    ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] Nuclei 결과 저장 완료 (scan_result_id={scan_result_id}, step={step})")
