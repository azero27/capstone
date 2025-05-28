import mysql.connector
import csv

def parse_domain_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    cursor.execute("INSERT INTO DomainFile (file_path) VALUES (%s)", (file_path,))
    domain_file_id = cursor.lastrowid  # 🔑 이 ID를 반환할 것

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        for row in reader:
            domain = row[0].strip()
            cursor.execute("""
                INSERT INTO DomainList (domain, domain_file_id) VALUES (%s, %s)
            """, (domain, domain_file_id))

    conn.commit()
    cursor.close()
    conn.close()
    return domain_file_id

def parse_port_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    # 포트 파일 테이블에 파일 정보 저장
    cursor.execute("INSERT INTO PortFile (file_path) VALUES (%s)", (file_path,))
    port_file_id = cursor.lastrowid

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # skip header
        for row in reader:
            port = int(row[0].strip())
            service = row[1].strip()
            cursor.execute("""
                INSERT INTO PortList (port, service, port_file_id)
                VALUES (%s, %s, %s)
            """, (port, service, port_file_id))

    conn.commit()
    cursor.close()
    conn.close()
    return port_file_id

def parse_s3_file(file_path: str) -> int:
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor()

    # S3 파일 테이블에 파일 정보 저장
    cursor.execute("INSERT INTO S3File (file_path) VALUES (%s)", (file_path,))
    s3_file_id = cursor.lastrowid

    with open(file_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # skip header
        for row in reader:
            bucket_name = row[0].strip()
            is_public = 1 if row[1].strip().upper() == "TRUE" else 0
            cursor.execute("""
                INSERT INTO S3List (s3_bucket, public, s3_file_id)
                VALUES (%s, %s, %s)
            """, (bucket_name, is_public, s3_file_id))

    conn.commit()
    cursor.close()
    conn.close()
    return s3_file_id

