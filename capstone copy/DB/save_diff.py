import mysql.connector
import difflib

def fetch_nuclei_results(scan_result_id):
    conn = mysql.connector.connect(
        host="localhost", user="DBA", password="1234", database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT target, vulnerability, risk_level, logs
        FROM NucleiResult
        WHERE scan_result_id = %s
    """, (scan_result_id,))
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return {row['target']: row for row in rows}

def save_nuclei_diff(curr_id, prev_id, diffs):
    conn = mysql.connector.connect(
        host="localhost", user="DBA", password="1234", database="SKYROUTE"
    )
    cursor = conn.cursor()
    for diff in diffs:
        cursor.execute("""
            INSERT INTO NucleiDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
            VALUES (%s, %s, %s, %s, %s)
        """, (curr_id, prev_id, diff['target'], diff['type'], diff['desc']))
    conn.commit()
    cursor.close()
    conn.close()

def compare_nuclei_results(prev_id, curr_id):
    prev = fetch_nuclei_results(prev_id)
    curr = fetch_nuclei_results(curr_id)

    diffs = []

    # removed
    for target in prev:
        if target not in curr:
            diffs.append({
                "target": target,
                "type": "removed",
                "desc": f"{target} 이(가) 더 이상 탐지되지 않음"
            })

    # added
    for target in curr:
        if target not in prev:
            diffs.append({
                "target": target,
                "type": "added",
                "desc": f"{target} 이(가) 새로 탐지됨"
            })

    # changed
    for target in curr:
        if target in prev:
            p = prev[target]
            c = curr[target]
            if p["risk_level"] != c["risk_level"] or p["vulnerability"] != c["vulnerability"]:
                diffs.append({
                    "target": target,
                    "type": "changed",
                    "desc": f"{target} 위험도 변경: {p['risk_level']} → {c['risk_level']}, 내용 변경 가능성"
                })

    if diffs:
        save_nuclei_diff(curr_id, prev_id, diffs)
        print(f"[+] nuclei diff {len(diffs)}건 저장 완료")
    else:
        print("[=] nuclei 변경 없음")


def get_prev_scan_result_id(scan_target_id: int, current_scan_result_id: int, tool_id: int) -> int:
    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE target_id = %s AND tool_id = %s AND id < %s
            ORDER BY id DESC
            LIMIT 1
        """, (scan_target_id, tool_id, current_scan_result_id))
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception as e:
        print(f"[ERROR] 이전 스캔 조회 실패: {e}")
        return None
    finally:
        cursor.close()
        conn.close()
