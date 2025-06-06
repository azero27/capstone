import mysql.connector
from datetime import datetime

def save_s3scanner_result(parsed_tuple, scan_result_id, step):
    bucket_results, file_objects = parsed_tuple  # ✅ 두 리스트로 분리

    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE",
        port=3306
    )
    cursor = conn.cursor()

    s3scanner_id_map = {}  # bucket_name → id 매핑

    for entry in bucket_results:
        # 1) 기존 ID (버킷 이름) 조회해서
        cursor.execute(
            "SELECT id FROM S3scannerResult WHERE scan_result_id=%s AND bucket_name=%s LIMIT 1",
            (scan_result_id, entry.get("bucket_name"))
        )
        row = cursor.fetchone()
        if row:
            # 이미 저장된 버킷이면 기존 id만 맵에 추가하고 INSERT 건너뛰기
            s3scanner_id_map[entry.get("bucket_name")] = row[0]
            continue


        cursor.execute("""
            INSERT INTO S3scannerResult (
                tool_id, scan_result_id, step, target, command,
                success, bucket_status, bucket_name,
                authusers_permission, allusers_permission, sensitive_files,
                file_type, log, start_time, end_time
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            entry.get("tool_id"),
            scan_result_id,
            step,
            entry.get("target"),
            entry.get("command"),
            1 if entry.get("success_failure") == "success" else 0,
            entry.get("bucket_status"),
            entry.get("bucket_name"),
            entry.get("authusers_permission"),
            entry.get("allusers_permission"),
            entry.get("sensitive_files"),
            entry.get("file_type"),
            entry.get("logs"),
            entry.get("start_time"),
            entry.get("end_time")
        ))
        s3scanner_id = cursor.lastrowid
        s3scanner_id_map[entry.get("bucket_name")] = s3scanner_id

    for file in file_objects:
        s3scanner_id = s3scanner_id_map.get(file.get("target"))
        if s3scanner_id:
            cursor.execute(
                 "SELECT 1 FROM S3scannerObject WHERE s3scanner_id=%s AND `object`=%s AND url=%s LIMIT 1",
                 (s3scanner_id, file.get("object"), file.get("url"))
             )
            if cursor.fetchone():
                 # 이미 저장된 거면 패스
                 continue

            cursor.execute("""
                INSERT INTO S3scannerObject (
                    s3scanner_id, object, object_type, object_size, url
                ) VALUES (%s, %s, %s, %s, %s)
            """, (
                s3scanner_id,
                file.get("object"),
                file.get("object_type"),
                file.get("object_size"),
                file.get("url")
            ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] S3ScannerResult 및 관련 객체 파일 저장 완료 (scan_result_id={scan_result_id})")
