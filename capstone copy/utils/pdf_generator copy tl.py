from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
from collections import defaultdict
from io import BytesIO
from reportlab.lib.utils import ImageReader
import tempfile
import os
import re
import pandas as pd
import seaborn as sns
from reportlab.lib.styles import ParagraphStyle
styles = getSampleStyleSheet()
styleN = styles['Normal']
styleN8 = ParagraphStyle('Normal8', parent=styleN, fontSize=8)

TOOL_RESULT_SOURCE_MAP = {
    "amass_result": "amass",
    "nuclei_result": "nuclei",
    "cloud_enum_result": "cloud_enum",
    "s3scanner_result": "s3scanner",
    "nmap_result": "nmap",
    "shadow_domain_result": "shadow_domain",
    "shadow_network_result": "shadow_network",
    "shadow_resource_result": "shadow_resource"
}

TOOL_TO_RESOURCE_TYPE = {
    "amass": "domain",
    "nuclei": "domain",
    "cloud_enum": "domain",
    "s3scanner": "s3",
    "nmap": "port",
    "shadow_domain": "domain",
    "shadow_network": "port",
    "shadow_resource": "s3"
}

def prepare_diff_records(report_data):
    from utils.mock_data import generate_mock_diff_records_tools, generate_mock_diff_records_shadow
    from utils.pdf_generator import TOOL_TO_RESOURCE_TYPE  # 사용 중이면
    
    def flatten_diff_records(records_grouped):
        flat = []
        for group in records_grouped:
            for k, v in group.items():
                source = k.replace("_result", "")
                for record in v:
                    record["source"] = source
                    record["resource_type"] = TOOL_TO_RESOURCE_TYPE.get(source, "unknown")
                    flat.append(record)
        return flat

    report_data["diff_records_tools"] = flatten_diff_records(generate_mock_diff_records_tools())
    report_data["diff_records_shadow"] = flatten_diff_records(generate_mock_diff_records_shadow())
    report_data["diff_records"] = report_data["diff_records_tools"] + report_data["diff_records_shadow"]
    
    return report_data

def generate_resource_change_chart_image(diff_records):
    color_map = {"added": "green", "removed": "red", "changed": "orange"}
    marker_map = {
        "amass": "v", "nuclei": "v", "shadow_domain": "v",
        "s3scanner": "o", "cloud_enum": "o", "shadow_resource": "o",
        "nmap": "s", "shadow_network": "s"
    }

    fig, ax = plt.subplots(figsize=(10, 6))
    targets = list(set([r["target"] for r in diff_records]))
    targets.sort()
    y_map = {t: i for i, t in enumerate(targets)}

    for record in diff_records:
        y = y_map[record["target"]]
        x = record["scan_result_id"]
        color = color_map.get(record["diff_type"], "gray")
        marker = marker_map.get(record["source"], "x")
        ax.scatter(x, y, color=color, marker=marker, s=80)

    ax.set_yticks(list(y_map.values()))
    ax.set_yticklabels(list(y_map.keys()), fontsize=7)
    ax.set_xlabel("Scan ID")
    ax.set_title("Resource Change Timeline")
    ax.grid(True)

    plt.tight_layout()
    tmpfile = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmpfile.name, bbox_inches='tight')
    plt.close()
    return tmpfile.name  # ⬅ 이걸 flowables에 Image()로 삽입하면 됩니다

def generate_resource_chart(discovered_resources: dict, chart_type='bar') -> BytesIO:
    labels = list(discovered_resources.keys())
    values = list(discovered_resources.values())

    fig, ax = plt.subplots(figsize=(5, 3))

    if chart_type == 'pie':
        ax.pie(values, labels=labels, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')  # 원형 유지
    else:
        bar_width = 0.4  # 막대 두께 조절
        colors_list = ['#A8DADC', '#FFB5A7', '#CDB4DB']  # 더 보기 좋은 색들
        ax.bar(labels, values, width=bar_width, color=colors_list[:len(labels)])
        ax.set_title("Discovered Resources", fontsize=12)
        ax.set_ylabel("Count", fontsize=10)

        ax.set_yticks(range(0, max(values)+1))
        ax.set_axisbelow(True)
        ax.grid(axis='y', linestyle='--', alpha=0.4)

    buf = BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='PNG', dpi=150)
    buf.seek(0)
    plt.close(fig)
    return buf
    
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
    width, height = A4

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

    discovered = overall.get("discovered_resources", {})
    if discovered:
        chart_img = generate_resource_chart(discovered, chart_type='bar')  # 또는 'pie'
        img = Image(chart_img, width=5*inch, height=3*inch)
        flowables.append(img)
        flowables.append(Spacer(1, 12))

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

    # Section: Resource Change Timeline (Diff Plot)
    diff_records = report_data.get("diff_records", [])  # 이미 있는 코드

    if diff_records:
        add_paragraph(f"<b>{section_index}. Resource Change Timeline</b>", 'Heading2')
        add_paragraph(
            "This section shows when each resource was added or removed over time.",
            'Normal'
        )
        flowables.append(Spacer(1, 12))

        # [추가] 그래프 이미지 생성
        # from charts.resource_change_chart import generate_resource_change_chart_image  # ❗모듈로 따로 빼도 되고 내부 함수로 둬도 됩니다

        chart_path = generate_resource_change_chart_image(diff_records)  # PNG 파일 경로 리턴
        flowables.append(Image(chart_path, width=7 * inch, height=3 * inch))  # ✅ 그대로 삽입

        flowables.append(Spacer(1, 12))
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
                title_key = "target" if "target" in findings[0] else \
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