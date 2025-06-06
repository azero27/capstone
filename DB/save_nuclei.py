import mysql.connector

def save_nuclei_result(item, scan_result_id, step):
    if not isinstance(item, dict):
        raise ValueError(f"Expected dict, got {type(item)}")

    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM NucleiResult
        WHERE scan_result_id = %s AND target = %s
    """, (scan_result_id, item.get("target")))
    count = cursor.fetchone()[0]
    if count > 0:
        print(f"[SKIP] 중복 target 저장 생략 → {item.get('target')}")
        cursor.close()
        conn.close()
        return

    cursor.execute("""
        INSERT INTO NucleiResult (
            tool_id, scan_result_id, step, target, command, success,
            vulnerability, risk_level, url, log, start_time, end_time
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        item.get("tool_id", 6),
        scan_result_id,
        step,
        item.get("target"),
        item.get("command"),
        item.get("success"),
        item.get("vulnerability"),
        item.get("risk_level"),
        item.get("url"),
        item.get("logs"),
        item.get("start_time"),
        item.get("end_time")
    ))

    conn.commit()
    cursor.close()
    conn.close()
    print("[+] Nuclei 결과 1개 DB 저장 완료")
