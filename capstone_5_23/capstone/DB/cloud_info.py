# DB/get_or_create_cloud_info.py

import mysql.connector

def get_or_create_cloud_info(ip: str, domain: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id FROM CloudInfo
        WHERE ip = %s AND domain = %s
    """, (ip, domain))

    result = cursor.fetchone()

    if result:
        cloud_info_id = result[0]
        print(f"[+] 기존 CloudInfo ID 반환: {cloud_info_id} ({ip}, {domain})")
    else:
        cursor.execute("""
            INSERT INTO CloudInfo (ip, domain)
            VALUES (%s, %s)
        """, (ip, domain))
        conn.commit()
        cloud_info_id = cursor.lastrowid
        print(f"[+] 새 CloudInfo 저장: {cloud_info_id} ({ip}, {domain})")

    cursor.close()
    conn.close()
    return cloud_info_id
