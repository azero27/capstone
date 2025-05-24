# DB/save_cloud_enum.py

import mysql.connector

def save_cloud_enum_result(results_main: list, results_files: list, scan_result_id: int, step: int):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE",
        port=3306
    )
    cursor = conn.cursor()

    cloud_enum_id_list = []

    for result in results_main:
        result["scan_result_id"] = scan_result_id
        result["step"] = step

        cursor.execute("""
            INSERT INTO CloudEnumResult (
                tool_id, target, command, success,
                log, start_time, end_time,
                scan_result_id, step
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            result["tool_id"],
            result["target"],
            result["command"],
            result["success_failure"],
            result["logs"],
            result["start_time"],
            result["end_time"],
            result["scan_result_id"],
            result["step"]
        ))

        cloud_enum_id_list.append(cursor.lastrowid)

    for file in results_files:
        bucket_index = file["bucket_index"]
        cloud_enum_id = cloud_enum_id_list[bucket_index]

        cursor.execute("""
            INSERT INTO CloudEnumFiles (
                cloud_enum_id,
                file
            ) VALUES (%s, %s)
        """, (
            cloud_enum_id,
            file["file_url"]
        ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] CloudEnum 결과 DB 저장 완료 (buckets={len(results_main)}, files={len(results_files)})")
