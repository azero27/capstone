from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
import matplotlib.pyplot as plt
from collections import defaultdict
from matplotlib.lines import Line2D
from io import BytesIO
from reportlab.lib.utils import ImageReader
import tempfile
import os
import re
import pandas as pd
import seaborn as sns
from reportlab.lib.styles import ParagraphStyle
import numpy as np

styles = getSampleStyleSheet()
styleN = styles['Normal']
styleN8 = ParagraphStyle('Normal8', parent=styleN, fontSize=8)
max_width = A4[0] - 2 * inch

plt.style.use('ggplot')

plt.rcParams.update({
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "axes.edgecolor": "black",
    "axes.linewidth": 1.2,
    "font.family": "DejaVu Sans",
    "text.color": "#333333"
})

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

color_map = {"added": "green", "removed": "red", "changed": "orange"}
marker_map = {
    "s3": "o",
    "port": "s",
    "domain": "v"
}
resource_label_map = {
    "domain": "Domain",
    "s3": "S3",
    "port": "Port"
}

def prepare_diff_records(report_data, selected_resources):
    from utils.mock_data import generate_mock_diff_records_tools, generate_mock_diff_records_shadow
    from utils.pdf_generator import TOOL_TO_RESOURCE_TYPE

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

    all_tools = flatten_diff_records(generate_mock_diff_records_tools())
    all_shadow = flatten_diff_records(generate_mock_diff_records_shadow())

    # Shadow 결과는 선택된 리소스에 따라 필터링
    filtered_shadow = [r for r in all_shadow if r["resource_type"] in selected_resources]

    # 도구 결과도 선택된 리소스에 따라 필터링
    filtered_tools = [r for r in all_tools if r["resource_type"] in selected_resources]

    report_data["diff_records_tools"] = filtered_tools
    report_data["diff_records_shadow"] = filtered_shadow
    report_data["diff_records"] = filtered_tools + filtered_shadow

    return report_data


def generate_diff_table(records):
    table_data = [["Target", "Diff Type", "Tool"]]
    for r in records:
        table_data.append([
            r.get("target", ""),
            r.get("diff_type", ""),
            r.get("source", ""),
            # str(r.get("scan_result_id", "")),
            # str(r.get("prev_scan_result_id", "")),
            # r.get("description", "")
        ])
    return table_data

def generate_resource_change_chart_image(diff_records):
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from datetime import datetime
    import tempfile

    plt.style.use('seaborn-whitegrid')

    fig, ax = plt.subplots(figsize=(10, 5), dpi=150)
    plt.subplots_adjust(bottom=0.3)

    # Prepare y-axis labels
    targets = sorted(set(r["target"] for r in diff_records))
    y_map = {t: i for i, t in enumerate(targets)}

    for r in diff_records:
        y = y_map[r["target"]]
        x = r["scan_result_id"]
        color = color_map.get(r["diff_type"], "gray")
        marker = marker_map.get(r["resource_type"], "x")
        ax.scatter(x, y, color=color, marker=marker, s=100, edgecolor='black')

    # Y-axis
    ax.set_yticks(list(y_map.values()))
    ax.set_yticklabels(list(y_map.keys()), fontsize=9)

    # Axis labels and title
    ax.set_xlabel("Scan ID", fontsize=11)
    ax.set_title("Resource Change Timeline", fontsize=13)
    ax.grid(True, linestyle='--', linewidth=0.5, alpha=0.5)

    # Remove internal legend
    # Add explanation text under graph
    tools_in_chart = {r["source"] for r in diff_records}
    types_in_chart = {r["diff_type"] for r in diff_records}

    legend_elements = []


    if "added" in types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='o', color='green', label='added (green)', linestyle='', markersize=8))
    if "removed" in types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='o', color='red', label='removed (red)', linestyle='', markersize=8))
    if "changed" in types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='o', color='orange', label='changed (orange)', linestyle='', markersize=8))

    # diff_records에서 리소스 타입 추출
    resource_types_in_chart = set(r.get("resource_type") for r in diff_records)

    # 기존 if 구조 그대로 유지해서 범례 추가
    if "domain" in resource_types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='v', color='black', label='Domain', linestyle='', markersize=8))
    if "s3" in resource_types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='o', color='black', label='S3', linestyle='', markersize=8))
    if "port" in resource_types_in_chart:
        legend_elements.append(Line2D([0], [0], marker='s', color='black', label='Port', linestyle='', markersize=8))

    # 범례 그리기
    ax.legend(handles=legend_elements, loc='lower center', bbox_to_anchor=(0.5, -0.35),
            ncol=2, fontsize=9, frameon=False)

    plt.tight_layout()
    tmpfile = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
    fig.savefig(tmpfile.name, bbox_inches='tight', dpi=200)
    plt.close()
    return tmpfile.name

def generate_resource_chart(discovered_resources: dict) -> BytesIO:
    labels = list(discovered_resources.keys())
    values = list(discovered_resources.values())

    x = np.arange(len(labels))  # x축 위치 지정
    width = 0.15                 # 막대 두께 고정

    color_map = {
        "s3_buckets": "#5c6f91",
        "open_ports": "#5c6f91",
        "subdomains": "#5c6f91"
    }
    colors = [color_map.get(label, "#1f77b4") for label in labels]

    plt.style.use('seaborn-whitegrid')
    fig, ax = plt.subplots(figsize=(8, 4), dpi=150)

    ax.bar(x, values, width=width, color=colors, edgecolor="black", linewidth=1)

    ax.set_title("Discovered Resources", loc='left', fontsize=13, pad=10)
    ax.set_ylabel("Count", fontsize=11)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=9)
    ax.tick_params(axis='y', labelsize=9)
    ax.grid(True, axis='y', linestyle='--', linewidth=0.5, alpha=0.6)

    plt.tight_layout()
    buf = BytesIO()
    plt.savefig(buf, format='PNG')
    buf.seek(0)
    plt.close()
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

    # Section 1: Overall Summary
    add_paragraph("<b>1. Overall Summary</b>", 'Heading2')
    add_paragraph("1.1 Number of Discovered Resources", 'Heading3')
    discovered = overall.get("discovered_resources", {})
    if discovered:
        chart_img = generate_resource_chart(discovered)
        flowables.append(Image(chart_img, width=5 * inch, height=3 * inch))
        flowables.append(Spacer(1, 12))
    for r, count in discovered.items():
        add_paragraph(f"{format_label(r)}: {count}")

    if "security_issues" in overall:
        add_paragraph("1.2 Number of Security Issues", 'Heading3')
        for level, count in overall["security_issues"].items():
            add_paragraph(f"{format_label(level)}: {count}")

    # Section 2~4: Resources
    section_index = 2
    for rtype in ["domain", "s3", "port"]:
        if rtype not in resources:
            continue
        rdata = resources[rtype]
        add_paragraph(f"<b>{section_index}. Resource Type: {rtype.upper()}</b>", 'Heading2')

        # Summary
        add_paragraph(f"{section_index}.1 Summary", 'Heading3')
        summary = rdata.get("summary", {})
        for k, v in summary.items():
            value = ", ".join(str(i) for i in normalize_list_field(v)) if isinstance(v, list) else str(v)
            add_paragraph(f"{format_label(k)}: {value}")
        if rdata.get("start_time"):
            add_paragraph(f"Scan Time: {rdata['start_time']}")

        # Findings
        add_paragraph(f"{section_index}.2 Findings", 'Heading3')
        findings = rdata.get("findings", [])
        if findings:
            if rtype == "s3":
                table_data = generate_s3_table(findings)
            elif rtype == "port":
                table_data = generate_port_table(findings)
            elif rtype == "domain":
                table_data = generate_domain_table(findings)
            else:
                table_data = []

            t = Table(table_data, hAlign='LEFT')
            t.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
            ]))
            flowables.append(t)
            flowables.append(Spacer(1, 10))

        section_index += 1

    # Section 5: Shadow IT
    shadow = resources.get("shadow")
    shadow_map = {
        "shadow_domain": "Shadow Domain",
        "shadow_network": "Shadow Network",
        "shadow_resource": "Shadow Resource"
    }
    shadow_has_data = shadow and any(s.get("findings") for s in shadow.values())

    if shadow_has_data:
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
                title_key = (
                    "target" if "target" in findings[0]
                    else "bucket" if "bucket" in findings[0]
                    else "port" if "port" in findings[0]
                    else list(findings[0].keys())[0]
                )
                table_data = generate_shadow_table(findings, title_key)
                t = Table(table_data, hAlign='LEFT')
                t.setStyle(TableStyle([
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey)
                ]))
                flowables.append(t)
                flowables.append(Spacer(1, 10))
            sub_index += 1
        section_index += 1

    # Section 6: Resource Change Timeline
    diff_records = report_data.get("diff_records", [])
    if diff_records:
        add_paragraph(f"<b>{section_index}. Resource Change Timeline</b>", 'Heading2')
        add_paragraph(
            "This section shows when each resource was added, removed, or changed over time.",
            'Normal'
        )
        flowables.append(Spacer(1, 12))
        chart_path = generate_resource_change_chart_image(diff_records)  # 포함된 legend 및 마커
        flowables.append(Image(chart_path, width=7 * inch, height=3 * inch))
        flowables.append(Spacer(1, 12))
    
    # Section 6.1~6.6: 리소스별 상세 변경 내역 테이블
    grouped = defaultdict(list)
    for rec in report_data.get("diff_records", []):
        grouped[rec["resource_type"]].append(rec)

    RESOURCE_ORDER = [rtype for rtype in ["s3", "domain", "port",
                                      "shadow_network", "shadow_resource", "shadow_domain"]
                  if rtype in grouped]
    for idx, rtype in enumerate(RESOURCE_ORDER, start=1):
        records = grouped.get(rtype, [])
        if not records:
            continue
        add_paragraph(f"<b>{section_index}.{idx} Detailed Changes by {rtype.upper()}</b>", 'Heading3')
        table_data = generate_diff_table(records)
        t = Table(table_data, colWidths=[max_width / len(table_data[0])] * len(table_data[0]), repeatRows=1)
        t.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.black),
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
            ('LEFTPADDING', (0,0), (-1,-1), 6),
            ('RIGHTPADDING', (0,0), (-1,-1), 6)
        ]))
        flowables.append(t)
        flowables.append(Spacer(1, 10))
    
    doc.build(flowables)