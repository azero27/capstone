from datetime import datetime
import mysql.connector

# DB/save_scan_result.py

import mysql.connector
from datetime import datetime

def save_scan_result_start(cloud_info_id: int, scan_setting_id: int) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        INSERT INTO ScanResult (cloud_info_id, scan_setting_id, start_time)
        VALUES (%s, %s, %s)
    """, (cloud_info_id, scan_setting_id, start_time))

    conn.commit()
    scan_result_id = cursor.lastrowid

    cursor.close()
    conn.close()

    print(f"[+] ScanResult 시작 저장 완료 (ID={scan_result_id})")
    return scan_result_id


def update_scan_result_end(scan_result_id: int):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    cursor.execute("""
        UPDATE ScanResult
        SET end_time = %s
        WHERE id = %s
    """, (end_time, scan_result_id))

    conn.commit()
    cursor.close()
    conn.close()

    print(f"[+] ScanResult 종료 시간 기록 완료 (ID={scan_result_id})")
