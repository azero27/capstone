import mysql.connector

def generate_data_from_db(scan_result_id):
    conn = mysql.connector.connect(
        host="localhost",
        user="DBA",
        password="1234",
        database="SKYROUTE"
    )
    cursor = conn.cursor(dictionary=True)

    raw_data = {}

    # 1. Nmap (PORT)
    cursor.execute("SELECT * FROM NmapResult WHERE scan_result_id = %s", (scan_result_id,))
    nmap_results = cursor.fetchall()
    raw_data["port"] = {
        "nmap_results": [{
            "parsed_nmap_result": nmap_results
        }]
    }

    # 2. S3Scanner (S3 버킷)
    cursor.execute("SELECT * FROM S3ScannerResult WHERE scan_result_id = %s", (scan_result_id,))
    s3scanner_results = cursor.fetchall()

    cursor.execute("""
        SELECT object_name, target
        FROM S3ScannerObject
        WHERE s3scanner_result_id IN (
            SELECT id FROM S3ScannerResult WHERE scan_result_id = %s
        )
    """, (scan_result_id,))
    sensitive_files = cursor.fetchall()

    # 버킷별 민감 파일 분류
    file_map = {}
    for f in sensitive_files:
        file_map.setdefault(f["target"], []).append(f["object_name"])

    raw_data["s3"] = {
        "s3scanner_results": [{
            "parsed_s3scanner_result": s3scanner_results,
            "parsed_s3scanner_sensitive_files": [
                {"object": obj, "target": bucket}
                for bucket, files in file_map.items()
                for obj in files
            ]
        }],
        "cloud_enum_results": {
            "cloudEnumDiscoveredFile": [],
            "cloudEnumScanResult": []
        }
    }

    # 3. Nuclei (DOMAIN 위험도)
    cursor.execute("SELECT * FROM NucleiResult WHERE scan_result_id = %s AND risk = 'high'", (scan_result_id,))
    nuclei_results = cursor.fetchall()
    raw_data["domain"] = {
        "amass_results": [],  # 필요한 경우 추가
        "nuclei_results": [{
            "nulcei_result": r
        } for r in nuclei_results]
    }

    # 4. Shadow Network
    cursor.execute("SELECT * FROM ShadowNetwork WHERE scan_result_id = %s", (scan_result_id,))
    raw_data["mock_shadow_network_result"] = cursor.fetchall()

    # 5. Shadow Domain
    cursor.execute("SELECT * FROM ShadowDomain WHERE scan_result_id = %s", (scan_result_id,))
    domains = cursor.fetchall()
    raw_data["mock_shadow_domain_result"] = {
        "dangling_dns": [d for d in domains if d["status"] == "dangling_dns"],
        "potential_exposure": [d for d in domains if d["status"] == "potential_exposure"],
        "linked_known_resource": [d for d in domains if d["status"] == "linked_known_resource"]
    }

    # 6. Shadow Resource
    cursor.execute("SELECT * FROM ShadowResource WHERE scan_result_id = %s", (scan_result_id,))
    raw_data["mock_shadow_resource_result"] = cursor.fetchall()

    cursor.close()
    conn.close()

    return raw_data
