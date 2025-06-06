import mysql.connector
from datetime import datetime

# 권한 설명
PERMISSION_EXPLANATIONS = {
    "READ": "Read – 버킷 내 파일 목록과 내용을 조회할 수 있음",
    "WRITE": "Write – 버킷에 파일을 업로드할 수 있음",
    "READ_ACP": "Read ACP – 접근 정책을 읽을 수 있음",
    "WRITE_ACP": "Write ACP – 접근 정책을 수정할 수 있음",
    "FULL_CONTROL": "Full Control – 모든 권한 보유 (읽기, 쓰기, 정책 읽기/쓰기)"
}

def parse_permissions(perm_str):
    perm_str = perm_str.strip("[]\" ")
    if not perm_str:
        return []
    return [p.strip() for p in perm_str.split(",")]

def describe_permissions(perm_list):
    return [PERMISSION_EXPLANATIONS.get(p, f"Unknown: {p}") for p in perm_list]

def analyze_shadow_resources():
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)

    # 최신 scan_result_id
    cursor.execute("SELECT MAX(id) as latest_id FROM ScanResult")
    latest_id = cursor.fetchone()["latest_id"]

    # 1. 정책상 공개 여부: S3List (s3_bucket, public)
    cursor.execute("SELECT s3_bucket, public FROM S3List")
    policy_data = cursor.fetchall()
    bucket_policy = {row["s3_bucket"]: bool(row["public"]) for row in policy_data}

    # 2. 실제 권한 상태: S3scannerResult (해당 scan_result_id)
    cursor.execute("""
        SELECT bucket_name, allusers_permission, authusers_permission
        FROM S3scannerResult
        WHERE scan_result_id = %s
    """, (latest_id,))
    scan_data = cursor.fetchall()

    # 3. 공개되면 안 되는 버킷만 필터링
    violations = []
    for item in scan_data:
        bucket = item["bucket_name"]
        alluser_perms = parse_permissions(item.get("allusers_permission", ""))
        authuser_perms = parse_permissions(item.get("authusers_permission", ""))
        is_actually_public = bool(alluser_perms)  # AllUsers 권한이 있으면 공개로 판단

        if bucket in bucket_policy and not bucket_policy[bucket] and is_actually_public:
            violations.append({
                "bucket": bucket,
                "allusers_permission": item["allusers_permission"],
                "authusers_permission": item["authusers_permission"],
                "scan_result_id": latest_id,
                "reason": "정책상 비공개 버킷이 AllUsers에게 공개됨"
            })

    # 4. ShadowResource에 저장
    for v in violations:
        cursor.execute("""
            INSERT INTO ShadowResource (bucket_name, allusers_permission, authusers_permission, reason, scan_result_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            v["bucket"],
            v["allusers_permission"],
            v["authusers_permission"],
            v["reason"],
            v["scan_result_id"]
        ))

    conn.commit()

    # 5. 로그 출력
    if not violations:
        print("모든 공개된 버킷은 정책상 허용된 상태입니다.")
    else:
        print("공개되면 안 되는 상태인데 실제로 공개된 버킷")
        for v in violations:
            print(f"\n- {v['bucket']}")
            alluser_desc = describe_permissions(parse_permissions(v["allusers_permission"]))
            authuser_desc = describe_permissions(parse_permissions(v["authusers_permission"]))
            print("  AllUsers 권한")
            for p in alluser_desc:
                print(f"    - {p}")
            print("  AuthUsers 권한")
            if authuser_desc:
                for p in authuser_desc:
                    print(f"    - {p}")
            else:
                print("    없음")

    cursor.close()
    conn.close()
