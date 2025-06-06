import mysql.connector
from datetime import datetime

def save_amass_result(parsed_result, scan_result_id, step):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    for item in parsed_result:
        cursor.execute("""
            INSERT INTO AmassResult (
                tool_id, scan_result_id, step, target,
                command, success, subdomain, log,
                start_time, end_time
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            item.get("tool_id", 3),
            scan_result_id,
            step,
            item.get("target", ""),
            item.get("command", ""),
            1 if item.get("status") == "success" else 0,
            item.get("subdomain", ""),
            item.get("logs", ""),
            item.get("start_time"),
            item.get("end_time")
        ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] Amass 결과 DB 저장 완료 ({len(parsed_result)}개)")
