import mysql.connector
import difflib

def save_nuclei_diff(scan_result_id):
    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        # 이전 스캔 ID 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 이전 결과 조회
        cursor.execute("""
            SELECT target, vulnerability, risk_level, url
            FROM NucleiResult
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_rows = cursor.fetchall()
        prev_map = {r["target"]: r for r in prev_rows}

        # 현재 결과 조회
        cursor.execute("""
            SELECT target, vulnerability, risk_level, url
            FROM NucleiResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_rows = cursor.fetchall()
        curr_map = {r["target"]: r for r in curr_rows}


        diffs = []

        # removed
        for target in prev_map:
            if target not in curr_map:
                diffs.append(("removed", target, f"{target} 이(가) 더 이상 탐지되지 않음"))

        # added
        for target in curr_map:
            if target not in prev_map:
                diffs.append(("added", target, f"{target} 이(가) 새로 탐지됨"))

        # changed
        fields_to_check = ["vulnerability", "risk_level", "url"]
        for target in curr_map:
            if target in prev_map:
                p = prev_map[target]
                c = curr_map[target]
                field_changes = []
                for field in fields_to_check:
                    if str(p.get(field)) != str(c.get(field)):
                        field_changes.append(f"{field}: {p.get(field)} → {c.get(field)}")
                if field_changes:
                    desc = f"{target} 변경사항 → " + ", ".join(field_changes)
                    diffs.append(("changed", target, desc))

        # 결과 저장
        if diffs:
            for diff_type, target, desc in diffs:
                cursor.execute("""
                    INSERT INTO NucleiDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, (scan_result_id, prev_id, target, diff_type, desc))
            conn.commit()
            print(f"[+] Nuclei 변화 {len(diffs)}건 저장 완료")
        else:
            print("[=] 변화 없음")

    except Exception as e:
        print(f"[ERROR] diff 비교 중 오류 발생: {e}")
    finally:
        cursor.close()
        conn.close()



def save_nmap_diff(scan_result_id):

    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        # 이전 scan_result_id 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 이전 결과 조회
        cursor.execute("""
            SELECT target, port_number, protocol, service_name, service_version
            FROM NmapResult
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_rows = cursor.fetchall()
        prev_map = {
            (r["target"], r["port_number"], r["protocol"]): r for r in prev_rows
        }

        # 현재 결과 조회
        cursor.execute("""
            SELECT target, port_number, protocol, service_name, service_version
            FROM NmapResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_rows = cursor.fetchall()
        curr_map = {
            (r["target"], r["port_number"], r["protocol"]): r for r in curr_rows
        }
        

        diffs = []

        # removed
        for key in prev_map:
            if key not in curr_map:
                t, port, proto = key
                diffs.append(("removed", t, port, proto, f"{t}:{port}/{proto} 이(가) 사라짐"))

        # added
        for key in curr_map:
            if key not in prev_map:
                t, port, proto = key
                diffs.append(("added", t, port, proto, f"{t}:{port}/{proto} 이(가) 새로 탐지됨"))

        # changed
        fields_to_check = ["service", "service_version"]
        for key in curr_map:
            if key in prev_map:
                p = prev_map[key]
                c = curr_map[key]
                changes = []
                for field in fields_to_check:
                    if str(p.get(field)) != str(c.get(field)):
                        changes.append(f"{field}: {p.get(field)} → {c.get(field)}")
                if changes:
                    t, port, proto = key
                    desc = f"{t}:{port}/{proto} 변경사항 → " + ", ".join(changes)
                    diffs.append(("changed", t, port, proto, desc))

        if diffs:
            for diff_type, target, port, proto, desc in diffs:
                cursor.execute("""
                    INSERT INTO NmapDiff (scan_result_id, prev_scan_result_id, target, port_number, protocol, diff_type, description)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (scan_result_id, prev_id, target, port, proto, diff_type, desc))
            conn.commit()
            print(f"[+] Nmap 변화 {len(diffs)}건 저장 완료")
        else:
            print("[=] 변화 없음")

    except Exception as e:
        print(f"[ERROR] Nmap diff 비교 중 오류 발생: {e}")
    finally:
        cursor.close()
        conn.close()


def save_amass_diff(scan_result_id):

    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="DBA",
            password="1234",
            database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        
        # 이전 scan_result_id 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 이전 결과 조회
        cursor.execute("""
            SELECT target, subdomain
            FROM AmassResult
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_rows = cursor.fetchall()
        prev_map = {r["subdomain"]: r for r in prev_rows}

        # 현재 결과 조회
        cursor.execute("""
            SELECT target, subdomain
            FROM AmassResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_rows = cursor.fetchall()
        curr_map = {r["subdomain"]: r for r in curr_rows}


        diffs = []

        # removed
        for subdomain in prev_map:
            if subdomain not in curr_map:
                diffs.append(("removed", subdomain, f"{subdomain} 이(가) 사라짐"))

        # added
        for subdomain in curr_map:
            if subdomain not in prev_map:
                diffs.append(("added", subdomain, f"{subdomain} 이(가) 새로 탐지됨"))


        if diffs:
            for diff_type, subdomain, desc in diffs:
                cursor.execute("""
                    INSERT INTO AmassDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, (scan_result_id, prev_id, subdomain, diff_type, desc))
            conn.commit()
            print(f"[+] Amass 변화 {len(diffs)}건 저장 완료")
        else:
            print("[=] 변화 없음")

    except Exception as e:
        print(f"[ERROR] Amass diff 비교 중 오류 발생: {e}")
    finally:
        cursor.close()
        conn.close()


def save_cloudenum_diff(scan_result_id):
    
    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        # 이전 scan_result_id 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 이전 CloudEnumResult 조회
        cursor.execute("""
            SELECT * FROM CloudEnumResult
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_rows = cursor.fetchall()
        prev_map = {r["target"]: r for r in prev_rows}

        # 현재 CloudEnumResult 조회
        cursor.execute("""
            SELECT * FROM CloudEnumResult
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_rows = cursor.fetchall()
        curr_map = {r["target"]: r for r in curr_rows}

        # 파일 리스트 조회 함수
        def get_files_by_result_id(result_ids):
            if not result_ids:
                return {}  # 빈 딕셔너리 반환하여 이후 로직에서 안전하게 처리 가능

            format_ids = ",".join(map(str, result_ids))
            cursor.execute(f"""
                SELECT cloud_enum_id, file FROM CloudEnumFile
                WHERE cloud_enum_id IN ({format_ids})
            """)
            file_map = {}
            for row in cursor.fetchall():
                file_map.setdefault(row["cloud_enum_id"], []).append(row["file"])
            return {k: sorted(set(v)) for k, v in file_map.items()}

        # 파일 목록 추출
        prev_files = get_files_by_result_id([r["id"] for r in prev_rows])
        curr_files = get_files_by_result_id([r["id"] for r in curr_rows])


        diffs = []

        # removed
        for target in prev_map:
            if target not in curr_map:
                diffs.append(("removed", target, f"{target} 이(가) 제거됨"))

        # added
        for target in curr_map:
            if target not in prev_map:
                diffs.append(("added", target, f"{target} 이(가) 새로 탐지됨"))

        # changed
        compare_fields = ["success", "log", "command", "step"]
        for target in curr_map:
            if target in prev_map:
                p = prev_map[target]
                c = curr_map[target]
                changes = []

                for field in compare_fields:
                    if str(p.get(field)) != str(c.get(field)):
                        changes.append(f"{field}: {p.get(field)} → {c.get(field)}")

                # file 비교
                p_files = prev_files.get(p["id"], [])
                c_files = curr_files.get(c["id"], [])
                if p_files != c_files:
                    changes.append(f"파일 목록 변경: {p_files} → {c_files}")

                if changes:
                    desc = f"{target} 변경사항 → " + ", ".join(changes)
                    diffs.append(("changed", target, desc))

        # 저장
        for diff_type, target, desc in diffs:
            cursor.execute("""
                INSERT INTO CloudEnumDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                VALUES (%s, %s, %s, %s, %s)
            """, (scan_result_id, prev_id, target, diff_type, desc))

        conn.commit()
        print(f"[+] CloudEnum 변화 {len(diffs)}건 저장 완료")

    except Exception as e:
        print(f"[ERROR] CloudEnum diff 비교 중 오류 발생: {e}")
    finally:
        cursor.close()
        conn.close()


def save_s3scanner_diff(scan_result_id):
    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        # 이전 scan_result_id 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 결과 조회
        cursor.execute("SELECT * FROM S3scannerResult WHERE scan_result_id = %s", (prev_id,))
        prev_rows = cursor.fetchall()
        cursor.execute("SELECT * FROM S3scannerResult WHERE scan_result_id = %s", (scan_result_id,))
        curr_rows = cursor.fetchall()

        prev_map = {r["bucket_name"]: r for r in prev_rows}
        curr_map = {r["bucket_name"]: r for r in curr_rows}

        # 객체 조회 함수
        def fetch_object_map(ids):
            if not ids:
                return {}

            cursor.execute(f"""
                SELECT * FROM S3scannerObject
                WHERE s3scanner_id IN ({','.join(map(str, ids))})
            """)
            result = {}
            for row in cursor.fetchall():
                sid = row["s3scanner_id"]
                result.setdefault(sid, {})[row["object"]] = row
            return result


        prev_ids = [r["id"] for r in prev_rows]
        curr_ids = [r["id"] for r in curr_rows]
        prev_obj_map = fetch_object_map(prev_ids)
        curr_obj_map = fetch_object_map(curr_ids)


        diffs = []

        # removed
        for bname in prev_map:
            if bname not in curr_map:
                diffs.append(("removed", bname, f"{bname} 이(가) 삭제됨"))

        # added
        for bname in curr_map:
            if bname not in prev_map:
                diffs.append(("added", bname, f"{bname} 이(가) 새로 추가됨"))

        # changed
        fields_to_check = [
            "bucket_status", "authusers_permission", "allusers_permission",
            "sensitive_files", "file_type"
        ]

        for bname in curr_map:
            if bname in prev_map:
                p = prev_map[bname]
                c = curr_map[bname]
                changes = []

                for field in fields_to_check:
                    if str(p.get(field)) != str(c.get(field)):
                        changes.append(f"{field}: {p.get(field)} → {c.get(field)}")

                # 오브젝트 비교 - 상세히
                p_objs = prev_obj_map.get(p["id"], {})
                c_objs = curr_obj_map.get(c["id"], {})
                p_keys = set(p_objs.keys())
                c_keys = set(c_objs.keys())

                added = c_keys - p_keys
                removed = p_keys - c_keys
                common = p_keys & c_keys

                if added:
                    changes.append(f"추가된 오브젝트: {', '.join(sorted(added))}")
                if removed:
                    changes.append(f"삭제된 오브젝트: {', '.join(sorted(removed))}")

                for name in common:
                    p_obj = p_objs[name]
                    c_obj = c_objs[name]
                    field_changes = []
                    for f in ["object_type", "object_size", "url"]:
                        if str(p_obj.get(f)) != str(c_obj.get(f)):
                            field_changes.append(f"{f}: {p_obj.get(f)} → {c_obj.get(f)}")
                    if field_changes:
                        changes.append(f"{name} 오브젝트 변경 → " + ", ".join(field_changes))

                if changes:
                    desc = f"{bname} 변경사항 → " + ", ".join(changes)
                    diffs.append(("changed", bname, desc))

        # 저장
        for diff_type, bucket_name, desc in diffs:
            cursor.execute("""
                INSERT INTO S3scannerDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                VALUES (%s, %s, %s, %s, %s)
            """, (scan_result_id, prev_id, bucket_name, diff_type, desc))

        conn.commit()
        print(f"[+] S3scanner 변화 {len(diffs)}건 저장 완료")

    except Exception as e:
        print(f"[ERROR] S3scanner diff 비교 중 오류 발생: {e}")
    finally:
        cursor.close()
        conn.close()


def save_shadow_diff(scan_result_id):
    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        # 현재 cloud_info_id 조회
        cursor.execute("""
            SELECT cloud_info_id FROM ScanResult
            WHERE id = %s
        """, (scan_result_id,))
        row = cursor.fetchone()
        if row:
            cloud_info_id = row["cloud_info_id"]
        else:
            print(f"[ERROR] scan_result_id={scan_result_id}에 해당하는 값 없음")
            return

        # 이전 scan_result_id 조회
        cursor.execute("""
            SELECT id FROM ScanResult
            WHERE cloud_info_id = %s AND id < %s
            ORDER BY id DESC LIMIT 1
        """, (cloud_info_id, scan_result_id))
        row = cursor.fetchone()
        if not row:
            print("[INFO] 최초 실행이므로 비교 생략")
            return
        prev_id = row["id"]

        # 이전 결과 조회
        cursor.execute("""
            SELECT port, actual_service, expected_service, reason
            FROM ShadowNetwork
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_net = {r["port"]: r for r in cursor.fetchall()}

        cursor.execute("""
            SELECT bucket_name, allusers_permission, authusers_permission, reason
            FROM ShadowResource
            WHERE scan_result_id = %s
        """, (prev_id,))
        prev_res = {r["bucket_name"]: r for r in cursor.fetchall()}

        # 현재 결과 조회
        cursor.execute("""
            SELECT port, actual_service, expected_service, reason
            FROM ShadowNetwork
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_net = {r["port"]: r for r in cursor.fetchall()}

        cursor.execute("""
            SELECT bucket_name, allusers_permission, authusers_permission, reason
            FROM ShadowResource
            WHERE scan_result_id = %s
        """, (scan_result_id,))
        curr_res = {r["bucket_name"]: r for r in cursor.fetchall()}

        diffs = []

        # Network 비교
        for port in prev_net:
            if port not in curr_net:
                diffs.append(("removed", "network", port, prev_net[port]["reason"]))
        for port in curr_net:
            if port not in prev_net:
                diffs.append(("added", "network", port, curr_net[port]["reason"]))

        # Resource 비교
        for bname in prev_res:
            if bname not in curr_res:
                diffs.append(("removed", "resource", bname, prev_res[bname]["reason"]))
        for bname in curr_res:
            if bname not in prev_res:
                diffs.append(("added", "resource", bname, curr_res[bname]["reason"]))

        # 결과 저장
        for diff_type, category, target, desc in diffs:
            if category == "network":
                cursor.execute("""
                    INSERT INTO ShadowNetworkDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, (scan_result_id, prev_id, target, diff_type, desc))
            else:
                cursor.execute("""
                    INSERT INTO ShadowResourceDiff (scan_result_id, prev_scan_result_id, target, diff_type, description)
                    VALUES (%s, %s, %s, %s, %s)
                """, (scan_result_id, prev_id, target, diff_type, desc))

        conn.commit()
        print(f"[+] Shadow Diff 저장 완료 ({len(diffs)}건)")

    except Exception as e:
        print(f"[ERROR] shadow diff 비교 중 오류 발생: {e}")

    finally:
        cursor.close()
        conn.close()