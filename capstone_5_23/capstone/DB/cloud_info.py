# DB/cloud_info.py
import mysql.connector

def save_cloud_info(ip: str, domain: str):
    import mysql.connector
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE",
            port=3306
        )
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO CloudInfo (ip, domain)
            VALUES (%s, %s)
        """, (ip, domain))
        conn.commit()
        print(f"[+] CloudInfo 저장 완료: {ip}, {domain}")
    except Exception as e:
        import traceback
        print(f"[ERROR] CloudInfo 저장 실패: {e}")
        traceback.print_exc()

