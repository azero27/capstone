from fpdf import FPDF
import os

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        self.set_font('Arial', '', 11)

    def add_title(self, text):
        self.set_font('Arial', 'B', 16)
        self.ln(8)
        self.cell(0, 10, text, ln=True)

    def add_subtitle(self, text):
        self.set_font('Arial', 'B', 13)
        self.ln(6)
        self.cell(0, 10, text, ln=True)

    def add_section(self, text):
        self.set_font('Arial', 'B', 11)
        self.ln(4)
        self.multi_cell(0, 8, text)

    def add_paragraph(self, text):
        self.set_font('Arial', '', 11)
        self.multi_cell(0, 8, text)

def normalize_list_field(field):
    if isinstance(field, list):
        return field
    elif isinstance(field, str) and field.strip() == "":
        return []
    elif field is None:
        return []
    else:
        return [field]

def format_label(key):
    return key.replace("_", " ").title()

def generate_pdf_report(report_data, save_path):
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    pdf = PDF()
    pdf.add_page()

    period = report_data.get("period", {"start": "N/A", "end": "N/A"})
    overall = report_data.get("overall_summary", {})
    resources = report_data.get("resources", {})

    pdf.add_title("Security Scan Report")
    pdf.add_paragraph(f"Scan Period: {period['start']} ~ {period['end']}")

    # 1. Overall Summary
    pdf.add_subtitle("1. Overall Summary")
    pdf.add_section("1.1 Number of Discovered Resources")
    for r, count in overall.get("discovered_resources", {}).items():
        pdf.add_paragraph(f"{format_label(r)}: {count}")

    if "security_issues" in overall:
        pdf.add_section("1.2 Number of Security Issues")
        for level, count in overall["security_issues"].items():
            pdf.add_paragraph(f"{format_label(level)}: {count}")

    section_index = 2
    for rtype in ["port", "s3", "domain"]:
        if rtype not in resources:
            continue

        rdata = resources[rtype]
        pdf.add_subtitle(f"{section_index}. Resource Type: {rtype.upper()}")

        # Summary
        pdf.add_section(f"{section_index}.1 Summary")
        summary = rdata.get("summary", {})
        if not summary:
            pdf.add_paragraph("   (No summary available)")
        else:
            for k, v in summary.items():
                value = ", ".join(str(i) for i in normalize_list_field(v)) if isinstance(v, list) else str(v)
                pdf.add_paragraph(f"{format_label(k)}: {value}")

        start_time = rdata.get("start_time")
        if start_time:
            pdf.add_paragraph(f"Scan Time: {start_time}")

        # Findings
        pdf.add_section(f"{section_index}.2 Findings")
        findings = rdata.get("findings", [])
        if not findings:
            pdf.add_paragraph("   (No findings reported)")
        else:
            for f in findings:
                target = f.get("target") or f.get("bucket") or f.get("domain")
                if target:
                    label = rtype.upper()
                    pdf.set_font('Arial', 'B', 11)
                    pdf.add_paragraph(f"{label}: {target}")
                    pdf.set_font('Arial', '', 11)

                # Risk Level
                if f.get("risk_level"):
                    pdf.add_paragraph(f"  - Risk Level: {f['risk_level'].upper()}")

                # Port-specific
                if rtype == "port":
                    svc = f.get("service_info", {})
                    port = ", ".join(normalize_list_field(f.get("port")))
                    pdf.add_paragraph(f"  Port: {port} ({', '.join(normalize_list_field(svc.get('service')))})")
                    pdf.add_paragraph(f"  - Protocol: {', '.join(normalize_list_field(svc.get('protocol')))}")
                    pdf.add_paragraph(f"  - Status: {', '.join(normalize_list_field(svc.get('status')))}")
                    pdf.add_paragraph(f"  - Version: {', '.join(normalize_list_field(svc.get('version')))}")

                # Details
                elif f.get("details"):
                    details = f["details"]
                    if isinstance(details, str) and "AuthUsers" in details and "AllUsers" in details:
                        pdf.add_paragraph(f"  - {details.strip()}")
                    elif isinstance(details, list):
                        for d in details:
                            pdf.add_paragraph(f"  - {str(d).strip()}")
                    else:
                        pdf.add_paragraph(f"  - Details: {str(details).strip()}")

                # Files
                sfiles = normalize_list_field(f.get("files"))
                if sfiles:
                    pdf.add_paragraph(f"  - Files: {', '.join(str(x) for x in sfiles)}")

                # Recommendation
                if f.get("recommendation"):
                    pdf.add_paragraph(f"  - Recommendation: {f['recommendation']}")

                # CNAME / URL
                if f.get("cname"):
                    cname_lines = str(f["cname"]).splitlines()
                    if cname_lines:
                        pdf.add_paragraph("  - CNAME Info:")
                        for line in cname_lines:
                            pdf.add_paragraph(f"      {line.strip()}")
                elif f.get("url_list"):
                    urls = normalize_list_field(f["url_list"])
                    pdf.add_paragraph(f"  - URL List: {', '.join(urls)}")
                elif f.get("url"):
                    pdf.add_paragraph(f"  - URL: {f['url']}")

                pdf.ln(2)


        section_index += 1

    # Shadow Section
    shadow = resources.get("shadow")  # 없으면 None

    shadow_map = {
        "shadow_domain": "Shadow Domain",
        "shadow_network": "Shadow Network",
        "shadow_resource": "Shadow Resource"
    }

    if shadow:
        pdf.add_subtitle(f"{section_index}. Shadow Analysis")
        shadow_sub_index = 1

        for skey, stitle in shadow_map.items():
            if skey not in shadow:
                continue

            sdata = shadow[skey]
            pdf.add_section(f"{section_index}.{shadow_sub_index} {stitle}")

            # Summary
            summary = sdata.get("summary", {})
            if summary:
                for k, v in summary.items():
                    value = ", ".join(str(i) for i in normalize_list_field(v)) if isinstance(v, list) else str(v)
                    pdf.add_paragraph(f"{format_label(k)}: {value}")
            else:
                pdf.add_paragraph("   (No summary available)")

            # Findings
            findings = sdata.get("findings", [])
            if findings:
                pdf.add_paragraph("Findings:")

                for f in findings: 
                    # 상위 식별자 출력 (예: Resource, Bucket, Port 등)
                    title_key = f.get("resource") or f.get("bucket") or f.get("port")
                    if title_key:
                        pdf.set_font('Arial', 'B', 11)
                        pdf.add_paragraph(f"{stitle} -> {title_key}")
                        pdf.set_font('Arial', '', 11)

                    # 이 부분이 반드시 f 루프 안에 들어가야 함
                    for fk, fv in f.items():
                        if fk in ("resource", "bucket", "port"):
                            continue  # 이미 타이틀로 출력됨
                        label = format_label(fk)
                        value = ", ".join(str(x) for x in normalize_list_field(fv)) if isinstance(fv, (list, dict)) else str(fv)
                        pdf.add_paragraph(f"    - {label}: {value}")

                    pdf.ln(1)  # 각 finding 간 줄바꿈

            else:
                pdf.add_paragraph("   (No findings reported)")

            shadow_sub_index += 1

        section_index += 1  # Shadow 분석이 포함되었을 때만 증가


    pdf.output(save_path)
