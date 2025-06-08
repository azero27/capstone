import mysql.connector
from typing import Optional, List, Dict
from datetime import datetime
from collections import defaultdict

def load_report_data_from_db(
    scan_result_ids: List[int],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    resource_types: Optional[List[str]] = None
) -> Dict:

    def in_resource_types(rtype: str) -> bool:
        return resource_types is None or rtype in resource_types

    def build_time_condition(field_name: str) -> (str, List):
        conditions = []
        values = []
        if start_time:
            conditions.append(f"{field_name} >= %s")
            values.append(start_time)
        if end_time:
            conditions.append(f"{field_name} <= %s")
            values.append(end_time)
        return " AND ".join(conditions), values

    def fetch_nuclei_high(cursor, scan_result_id: int) -> List[Dict]:
        cursor.execute("""
            SELECT target, url, vulnerability, risk_level
            FROM NucleiResult
            WHERE scan_result_id = %s AND risk_level = 'high'
        """, (scan_result_id,))
        return cursor.fetchall()

    def build_shadow_domain_diff(prev_results, curr_results, prev_scan_id, curr_scan_id) -> List[Dict]:
        prev_map = {
            (r["target"], r.get("vulnerability", "")): r
            for r in prev_results
        }
        curr_map = {
            (r["target"], r.get("vulnerability", "")): r
            for r in curr_results
        }

        prev_keys = set(prev_map.keys())
        curr_keys = set(curr_map.keys())

        added = curr_keys - prev_keys
        removed = prev_keys - curr_keys
        changed = {
            k for k in (prev_keys & curr_keys)
            if prev_map[k].get("url") != curr_map[k].get("url")
        }

        diff = []
        for k in added:
            r = curr_map[k]
            diff.append({"scan_result_id": curr_scan_id, "prev_scan_result_id": prev_scan_id,
                         "target": r["target"], "vulnerability": r.get("vulnerability", ""),
                         "diff_type": "added", "resource_type": "shadow_domain", "source": "shadow_domain"})
        for k in removed:
            r = prev_map[k]
            diff.append({"scan_result_id": curr_scan_id, "prev_scan_result_id": prev_scan_id,
                         "target": r["target"], "vulnerability": r.get("vulnerability", ""),
                         "diff_type": "removed", "resource_type": "shadow_domain", "source": "shadow_domain"})
        for k in changed:
            r = curr_map[k]
            diff.append({"scan_result_id": curr_scan_id, "prev_scan_result_id": prev_scan_id,
                         "target": r["target"], "vulnerability": r.get("vulnerability", ""),
                         "diff_type": "changed", "resource_type": "shadow_domain", "source": "shadow_domain"})
        return diff

    try:
        conn = mysql.connector.connect(
            host="localhost", user="DBA", password="1234", database="SKYROUTE"
        )
        cursor = conn.cursor(dictionary=True)

        report_data = {
            "period": {"start": start_time or "(unspecified)", "end": end_time or "(unspecified)"},
            "overall_summary": {"discovered_resources": {}, "security_issues": {}},
            "resources": {}, "diff_records": []
        }

        format_ids = ", ".join(str(i) for i in scan_result_ids)

        
        # Port
        if in_resource_types("port"):
            query = f"""
                SELECT port_number, protocol, service_name, service_version, target, start_time 
                FROM NmapResult 
                WHERE scan_result_id IN ({format_ids})
            """
            time_cond, time_vals = build_time_condition("start_time")

            if time_cond:
                query += f" AND {time_cond}"
            cursor.execute(query, time_vals)
            rows = cursor.fetchall()
            findings = [
                {
                    "port": [r["port_number"]],
                    "service_info": {
                        "protocol": [r["protocol"]],
                        "service": [r["service_name"]],
                        "version": [r["service_version"]],
                        "status": ["open"]
                    },
                    "target": r["target"]
                }
                for r in rows
            ]
            if findings:
                report_data["resources"]["port"] = {
                    "summary": {"count": len(findings)},
                    "findings": findings,
                    "start_time": str(rows[0]["start_time"])
                }
                report_data["overall_summary"]["discovered_resources"]["port"] = len(findings)

        # S3
        if in_resource_types("s3"):
            query = f"""
                SELECT R.bucket_name, R.allusers_permission, R.authusers_permission, R.start_time, O.object
                FROM S3scannerResult R
                LEFT JOIN S3scannerObject O ON R.id = O.s3scanner_id
                WHERE R.scan_result_id IN ({format_ids})
            """
            time_cond, time_vals = build_time_condition("R.start_time")
            if time_cond:
                query += f" AND {time_cond}"
            cursor.execute(query, time_vals)
            rows = cursor.fetchall()

            s3_buckets = defaultdict(lambda: {"files": [], "details": ""})

            for row in rows:
                b = row["bucket_name"]
                if row["object"]:
                    s3_buckets[b]["files"].append(row["object"])
                perms = []
                if row["allusers_permission"]:
                    perms.append(f"AllUsers: {row['allusers_permission']}")
                if row["authusers_permission"]:
                    perms.append(f"AuthUsers: {row['authusers_permission']}")
                s3_buckets[b]["details"] = "; ".join(perms) or "Private"

            findings = [
                {"bucket": b, "files": info["files"], "details": info["details"]}
                for b, info in s3_buckets.items()
            ]
            if findings:
                report_data["resources"]["s3"] = {
                    "summary": {"count": len(findings)},
                    "findings": findings
                }
                report_data["overall_summary"]["discovered_resources"]["s3"] = len(findings)

        # Domain
        if in_resource_types("domain"):
            query = f"SELECT target, url, vulnerability, risk_level, start_time FROM NucleiResult WHERE scan_result_id IN ({format_ids})"
            time_cond, time_vals = build_time_condition("start_time")
            if time_cond:
                query += f" AND {time_cond}"
            cursor.execute(query, time_vals)
            rows = cursor.fetchall()

            findings = []
            for r in rows:
                urls = r["url"].strip().splitlines() if r["url"] else []
                findings.append({
                    "domain": r["target"],
                    "issue": r["risk_level"],
                    "cname": urls,
                    "vuln": r.get("vulnerability", "")
                })
            if findings:
                report_data["resources"]["domain"] = {
                    "summary": {"count": len(findings)},
                    "findings": findings,
                    "start_time": str(rows[0]["start_time"])
                }
                report_data["overall_summary"]["discovered_resources"]["domain"] = len(findings)

        # Shadow Network
        if in_resource_types("shadow_network"):
            query = f"SELECT port, actual_service, expected_service, reason FROM ShadowNetwork WHERE scan_result_id IN ({format_ids})"
            cursor.execute(query)
            rows = cursor.fetchall()
            if rows:
                report_data["resources"].setdefault("shadow", {})["shadow_network"] = {
                    "summary": {"count": len(rows)},
                    "findings": rows
                }

        # Shadow Resource
        if in_resource_types("shadow_resource"):
            query = f"SELECT bucket_name, allusers_permission, authusers_permission, reason FROM ShadowResource WHERE scan_result_id IN ({format_ids})"
            cursor.execute(query)
            rows = cursor.fetchall()
            findings = []
            for r in rows:
                perms = []
                if r["allusers_permission"]:
                    perms.append(f"AllUsers: {r['allusers_permission']}")
                if r["authusers_permission"]:
                    perms.append(f"AuthUsers: {r['authusers_permission']}")
                findings.append({
                    "bucket": r["bucket_name"],
                    "details": "; ".join(perms) or "Private",
                    "reason": r["reason"]
                })
            if findings:
                report_data["resources"].setdefault("shadow", {})["shadow_resource"] = {
                    "summary": {"count": len(findings)},
                    "findings": findings
                }
        # Shadow Domain 추출: NucleiResult 중 risk_level이 high인 것
        if in_resource_types("shadow_domain"):
            query = f"""
                SELECT target, url, vulnerability, risk_level, start_time
                FROM NucleiResult 
                WHERE scan_result_id IN ({format_ids}) AND risk_level = 'high'
            """
            time_cond, time_vals = build_time_condition("start_time")
            if time_cond:
                query += f" AND {time_cond}"
            cursor.execute(query, time_vals)
            rows = cursor.fetchall()

            shadow_findings = []
            for r in rows:
                urls = r["url"].strip().splitlines() if r["url"] else []
                shadow_findings.append({
                    "domain": r["target"],
                    "issue": r["risk_level"],
                    "cname": urls,
                    "vuln": r.get("vulnerability", "")
                })

            if shadow_findings:
                report_data["resources"].setdefault("shadow", {})["shadow_domain"] = {
                    "summary": {"count": len(shadow_findings)},
                    "findings": shadow_findings
                }


        # Diff
        diff_tables = [
            ("NmapDiff", "port", "nmap"),
            ("NucleiDiff", "domain", "nuclei"),
            ("AmassDiff", "domain", "amass"),
            ("S3scannerDiff", "s3", "s3scanner"),
            ("CloudEnumDiff", "domain", "cloud_enum"),
            ("ShadowNetworkDiff", "port", "shadow_network"),
            ("ShadowResourceDiff", "s3", "shadow_resource")
        ]

        for entry in diff_tables:
            if len(entry) == 3:
                table, rtype, source = entry
            else:
                continue
            if not in_resource_types(rtype):
                continue
            query = f"SELECT * FROM {table} WHERE scan_result_id IN ({format_ids})"
            cursor.execute(query)
            rows = cursor.fetchall()
            for row in rows:
                row["resource_type"] = rtype
                row["source"] = source
                report_data["diff_records"].append(row)

        # Shadow Domain Diff
        if in_resource_types("shadow_domain") and len(scan_result_ids) >= 2:
            sorted_ids = sorted(scan_result_ids)
            prev_id, curr_id = sorted_ids[-2], sorted_ids[-1]
            prev = fetch_nuclei_high(cursor, prev_id)
            curr = fetch_nuclei_high(cursor, curr_id)
            diff_rows = build_shadow_domain_diff(prev, curr, prev_id, curr_id)
            report_data["diff_records"].extend(diff_rows)

        cursor.close()
        conn.close()
        return report_data

    except Exception as e:
        print("[ERROR] Failed to load report data from DB:", e)
        return {}



def build_shadow_domain_diff(
    prev_results: List[Dict], curr_results: List[Dict],
    prev_scan_id: int, curr_scan_id: int
) -> List[Dict]:
    prev_map = {
        (r["target"], r.get("vulnerability", "")): r
        for r in prev_results if r.get("risk_level") == "high"
    }
    curr_map = {
        (r["target"], r.get("vulnerability", "")): r
        for r in curr_results if r.get("risk_level") == "high"
    }

    prev_keys = set(prev_map.keys())
    curr_keys = set(curr_map.keys())

    added_keys = curr_keys - prev_keys
    removed_keys = prev_keys - curr_keys
    common_keys = prev_keys & curr_keys

    changed_keys = {
        k for k in common_keys
        if prev_map[k].get("url") != curr_map[k].get("url")
    }

    diff_records = []

    for key in added_keys:
        r = curr_map[key]
        diff_records.append({
            "scan_result_id": curr_scan_id,
            "prev_scan_result_id": prev_scan_id,
            "target": r["target"],
            "vulnerability": r.get("vulnerability", ""),
            "diff_type": "added",
            "resource_type": "shadow_domain",
            "source": "shadow_domain"
        })

    for key in removed_keys:
        r = prev_map[key]
        diff_records.append({
            "scan_result_id": curr_scan_id,
            "prev_scan_result_id": prev_scan_id,
            "target": r["target"],
            "vulnerability": r.get("vulnerability", ""),
            "diff_type": "removed",
            "resource_type": "shadow_domain",
            "source": "shadow_domain"
        })

    for key in changed_keys:
        r = curr_map[key]
        diff_records.append({
            "scan_result_id": curr_scan_id,
            "prev_scan_result_id": prev_scan_id,
            "target": r["target"],
            "vulnerability": r.get("vulnerability", ""),
            "diff_type": "changed",
            "resource_type": "shadow_domain",
            "source": "shadow_domain"
        })

    return diff_records