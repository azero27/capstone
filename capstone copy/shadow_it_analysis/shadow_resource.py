# 1. 공개 정책 정의 (DB에서 가져왔다고 가정)
bucket_public_policy = {
    "2025-skyroute": False,
    "2025-skyroute7": True,
    "capstone-skyroute": True,
    "config-bucket-351818465660": False,
    "public.sskyroute": True,
    "public.sskyroute.com": True,
    "skyroute-private": True,
    "skyroute-test": True,
    "skyroute-userdata": False,
    "skyroute6": True,
    "skyroute7": True,
    "skyroute": True,
    "sskyroute-private": True,
    "sskyroute-test": False,
    "sskyroute-userdata": False,
    "sskyroute.com": True,
    "tmzoslddydqjzlt": True,
    "dataset.sskyroute.com": True
}

# 2. s3scanner 결과 정의 (DB에서 불러온 JSON이라고 가정)
scan_result = {
  "parsed_s3scanner_result": [
    {
      "bucket_name": "sskyroute-userdata",
      "allusers_permission": "[FULL_CONTROL]",
      "authusers_permission": "[READ_ACP]"
    },
    {
      "bucket_name": "sskyroute",
      "allusers_permission": "[READ, READ_ACP]",
      "authusers_permission": "[]"
    },
    {
      "bucket_name": "skyroute7",
      "allusers_permission": "[READ, READ_ACP]",
      "authusers_permission": "[READ, READ_ACP]"
    },
    {
      "bucket_name": "sskyroute-private",
      "allusers_permission": "[READ, READ_ACP]",
      "authusers_permission": "[]"
    },
    {
      "bucket_name": "sskyroute-test",
      "allusers_permission": "[READ, READ_ACP]",
      "authusers_permission": "[]"
    }
  ]
}

# 3. 권한 설명 매핑
PERMISSION_EXPLANATIONS = {
    "READ": "Read – 버킷 내 파일 목록과 내용을 조회할 수 있음",
    "WRITE": "Write – 버킷에 파일을 업로드할 수 있음",
    "READ_ACP": "Read ACP – 접근 정책을 읽을 수 있음",
    "WRITE_ACP": "Write ACP – 접근 정책을 수정할 수 있음",
    "FULL_CONTROL": "Full Control – 모든 권한 보유 (읽기, 쓰기, 정책 읽기/쓰기)"
}

# 4. 유틸 함수들
def parse_permissions(perm_str):
    perm_str = perm_str.strip("[]\" ")
    if not perm_str:
        return []
    return [p.strip() for p in perm_str.split(",")]

def describe_permissions(perm_list):
    return [PERMISSION_EXPLANATIONS.get(p, f" Unknown: {p}") for p in perm_list]

def get_actual_public_buckets_with_permissions(scan_result):
    public_buckets = {}
    for item in scan_result.get("parsed_s3scanner_result", []):
        allusers_perm = item.get("allusers_permission", "")
        perm_list = parse_permissions(allusers_perm)
        if perm_list:  # 하나라도 있으면
            bucket_name = item["bucket_name"]
            public_buckets[bucket_name] = {
                "allusers_permission": item.get("allusers_permission", ""),
                "authusers_permission": item.get("authusers_permission", "")
            }
    return public_buckets

# 5. 메인 검사 및 출력 함수
def show_violating_buckets_verbose(bucket_public_policy, scan_result):
    public_buckets = get_actual_public_buckets_with_permissions(scan_result)
    violating = {
        bucket: perms
        for bucket, perms in public_buckets.items()
        if bucket in bucket_public_policy and not bucket_public_policy[bucket]
    }

    if not violating:
        print("모든 공개된 버킷은 정책상 허용된 상태입니다.")
        return

    print("공개되면 안 되는 상태인데 실제로 공개된 버킷")
    for bucket, perms in violating.items():
        print(f"\n- {bucket}")
        alluser_perms = parse_permissions(perms["allusers_permission"])
        authuser_perms = parse_permissions(perms["authusers_permission"])

        if alluser_perms:
            print("  AllUsers 권한")
            for p in describe_permissions(alluser_perms):
                print(f"    - {p}")
        else:
            print("  AllUsers 권한 없음")

        if authuser_perms:
            print("  AuthUsers 권한")
            for p in describe_permissions(authuser_perms):
                print(f"    - {p}")
        else:
            print("  AuthUsers 권한 없음")

# 6. 실행
show_violating_buckets_verbose(bucket_public_policy, scan_result)
