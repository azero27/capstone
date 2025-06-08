from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
import re
from reportlab.lib.styles import ParagraphStyle
styles = getSampleStyleSheet()
styleN = styles['Normal']
styleN8 = ParagraphStyle('Normal8', parent=styleN, fontSize=8)


def extract_permission(details: str, key: str) -> str:
    match = re.search(rf'{key}:\s*(\[.*?\])', details)
    return match.group(1) if match else "[]"

def normalize_list_field(field):
    if isinstance(field, list):
        return field
    elif isinstance(field, str) and field.strip() == "":
        return []
    elif isinstance(field, str):
        return [field]
    elif isinstance(field, (int, float)):
        return [str(field)]
    else:
        return []

def format_label(key):
    return key.replace("_", " ").title()

def generate_s3_table(findings):
    table_data = [["Bucket", "AuthUsers", "AllUsers", "Sensitive Files"]]
    for f in findings:
        table_data.append([
            f.get("bucket", ""),
            extract_permission(f.get("details", ""), "AuthUsers"),
            extract_permission(f.get("details", ""), "AllUsers"),
            ", ".join(f.get("files", []))
        ])
    return table_data

def generate_port_table(findings):
    table_data = [["Port", "Protocol", "Service", "Status", "Version"]]
    for f in findings:
        svc = f.get("service_info", {})
        table_data.append([
            ", ".join(map(str, f.get("port", []))),
            ", ".join(svc.get("protocol", [])),
            ", ".join(svc.get("service", [])),
            ", ".join(svc.get("status", [])),
            ", ".join(svc.get("version", [])),
        ])
    return table_data

styles = getSampleStyleSheet()
styleN = styles['Normal']

def generate_domain_table(findings):
    table_data = [["Domain", "Issue", "CNAME Info"]]
    for f in findings:
        domain = f.get("domain", "")
        issue = f.get("issue", "")
        cname = f.get("cname", "")

        # 줄바꿈 정리
        if isinstance(cname, list):
            cname = ", ".join(cname)
        elif isinstance(cname, str):
            cname = cname.replace("\\n", "\n").replace("\t", "").strip()

        table_data.append([
            Paragraph(domain, styleN8),
            Paragraph(issue, styleN8),
            Paragraph(cname, styleN8)
        ])

    return table_data

def generate_shadow_table(findings, title_key):
    headers = [title_key] + [k for k in findings[0].keys() if k != title_key]
    table_data = [headers]
    for f in findings:
        row = [f.get(title_key, "")]
        for k in headers[1:]:
            v = f.get(k, "")
            if isinstance(v, list):
                v = ", ".join(map(str, v))
            row.append(v)
        table_data.append(row)
    return table_data

def generate_pdf_report(report_data, save_path):
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    doc = SimpleDocTemplate(save_path, pagesize=A4)
    styles = getSampleStyleSheet()
    flowables = []

    def add_paragraph(text, style='Normal', space=6):
        flowables.append(Paragraph(text, styles[style]))
        flowables.append(Spacer(1, space))

    period = report_data.get("period", {"start": "N/A", "end": "N/A"})
    overall = report_data.get("overall_summary", {})
    resources = report_data.get("resources", {})

    add_paragraph("<b>Security Scan Report</b>", 'Title', 12)
    add_paragraph(f"Scan Period: {period['start']} ~ {period['end']}", 'Normal')

    add_paragraph("<b>1. Overall Summary</b>", 'Heading2')
    add_paragraph("1.1 Number of Discovered Resources", 'Heading3')
    for r, count in overall.get("discovered_resources", {}).items():
        add_paragraph(f"{format_label(r)}: {count}")

    if "security_issues" in overall:
        add_paragraph("1.2 Number of Security Issues", 'Heading3')
        for level, count in overall["security_issues"].items():
            add_paragraph(f"{format_label(level)}: {count}")

    section_index = 2
    for rtype in ["port", "s3", "domain"]:
        if rtype not in resources:
            continue
        rdata = resources[rtype]
        add_paragraph(f"<b>{section_index}. Resource Type: {rtype.upper()}</b>", 'Heading2')
        add_paragraph(f"{section_index}.1 Summary", 'Heading3')
        summary = rdata.get("summary", {})
        for k, v in summary.items():
            value = ", ".join(str(i) for i in normalize_list_field(v)) if isinstance(v, list) else str(v)
            add_paragraph(f"{format_label(k)}: {value}")

        start_time = rdata.get("start_time")
        if start_time:
            add_paragraph(f"Scan Time: {start_time}")

        add_paragraph(f"{section_index}.2 Findings", 'Heading3')
        findings = rdata.get("findings", [])
        if findings:
            if rtype == "s3":
                table_data = generate_s3_table(findings)
                t = Table(table_data, hAlign='LEFT')  # ← 이 줄 필수
            elif rtype == "port":
                table_data = generate_port_table(findings)
                t = Table(table_data, hAlign='LEFT')  # ← 이 줄 필수
            elif rtype == "domain":
                table_data = generate_domain_table(findings)
                t = Table(table_data, colWidths=[120, 120, 250], hAlign='LEFT')
            else:
                table_data = []
                t = Table(table_data, hAlign='LEFT')

            t.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)
            ]))
            flowables.append(t)
            flowables.append(Spacer(1, 10))
        section_index += 1

    shadow = resources.get("shadow")
    shadow_map = {
        "shadow_domain": "Shadow Domain",
        "shadow_network": "Shadow Network",
        "shadow_resource": "Shadow Resource"
    }
    if shadow:
        add_paragraph(f"<b>{section_index}. Shadow Analysis</b>", 'Heading2')
        sub_index = 1
        for skey, stitle in shadow_map.items():
            if skey not in shadow:
                continue
            sdata = shadow[skey]
            add_paragraph(f"{section_index}.{sub_index} {stitle}", 'Heading3')
            summary = sdata.get("summary", {})
            for k, v in summary.items():
                value = ", ".join(str(i) for i in normalize_list_field(v)) if isinstance(v, list) else str(v)
                add_paragraph(f"{format_label(k)}: {value}")

            findings = sdata.get("findings", [])
            if findings:
                title_key = "resource" if "resource" in findings[0] else \
                            "bucket" if "bucket" in findings[0] else \
                            "port" if "port" in findings[0] else list(findings[0].keys())[0]
                table_data = generate_shadow_table(findings, title_key)
                t = Table(table_data, hAlign='LEFT')
                t.setStyle(TableStyle([
                    ('GRID', (0,0), (-1,-1), 0.5, colors.black),
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), colors.lightgrey)
                ]))
                flowables.append(t)
                flowables.append(Spacer(1, 10))
            sub_index += 1
    doc.build(flowables)