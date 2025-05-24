import mysql.connector
from datetime import datetime

# 설정 저장 (최초 또는 변경 시)
def save_scan_setting(period: int):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    # 이전 설정이 있다면 stop_time을 현재로 업데이트
    cursor.execute("SELECT id FROM ScanSetting ORDER BY id DESC LIMIT 1")
    last_setting = cursor.fetchone()
    if last_setting:
        cursor.execute("""
            UPDATE ScanSetting SET stop_time = %s WHERE id = %s
        """, (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), last_setting[0]))

    # 새 설정 삽입
    start_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        INSERT INTO ScanSetting (period, start_time, stop_time)
        VALUES (%s, %s, NULL)
    """, (period, start_time))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] ScanSetting 저장 완료 (period={period})")

# 현재 사용 중인 주기 조회 (가장 최신 레코드의 id 기준)
def latest_scan_setting() -> int:
    import mysql.connector
    from datetime import datetime

    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM ScanSetting ORDER BY id DESC LIMIT 1")
    result = cursor.fetchone()

    if result:
        setting_id = result[0]
    else:
        # 기본 주기 60분으로 삽입
        cursor.execute("""
            INSERT INTO ScanSetting (period, start_time, stop_time)
            VALUES (%s, %s, NULL)
        """, (60, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        conn.commit()
        setting_id = cursor.lastrowid
        print(f"[+] 기본 ScanSetting 저장됨 (id={setting_id}, period=60)")

    cursor.close()
    conn.close()
    return setting_id

