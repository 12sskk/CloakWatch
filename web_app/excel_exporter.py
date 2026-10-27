import os
import io
import datetime
from typing import List, Dict, Any
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

def build_excel_report(scan_results: List[Dict[str, Any]], scan_meta: Dict[str, Any] = None) -> io.BytesIO:
    """
    Generates a professional multi-sheet Excel workbook from scan results.
    Sheets:
      1. Executive Summary: Key scan metrics, KPI breakdown, and risk thresholds
      2. Threat Assessments: Target URLs, CloakScore (0-100), Verdict, Category & 5 Sub-Scores
      3. Differential Analysis: Pairwise comparisons (Status, Redirects, Cosine Sim, Visual SSIM)
      4. Raw Probe Telemetry: Per-profile raw observations (User-Agent, status code, size, latency)
    """
    wb = Workbook()
    
    # Common Styles
    font_title = Font(name="Calibri", size=16, bold=True, color="FFFFFF")
    font_section = Font(name="Calibri", size=12, bold=True, color="1E293B")
    font_header = Font(name="Calibri", size=11, bold=True, color="FFFFFF")
    font_bold = Font(name="Calibri", size=10, bold=True)
    font_regular = Font(name="Calibri", size=10)
    font_small = Font(name="Calibri", size=9, italic=True, color="64748B")
    
    fill_navy = PatternFill(start_color="0F172A", end_color="0F172A", fill_type="solid")
    fill_header = PatternFill(start_color="1E293B", end_color="1E293B", fill_type="solid")
    fill_sub_header = PatternFill(start_color="334155", end_color="334155", fill_type="solid")
    fill_zebra = PatternFill(start_color="F8FAFC", end_color="F8FAFC", fill_type="solid")
    
    # Verdict fills
    fill_malicious = PatternFill(start_color="FEE2E2", end_color="FEE2E2", fill_type="solid")
    font_malicious = Font(name="Calibri", size=10, bold=True, color="991B1B")
    
    fill_safe = PatternFill(start_color="DCFCE7", end_color="DCFCE7", fill_type="solid")
    font_safe = Font(name="Calibri", size=10, bold=True, color="166534")

    thin_border = Border(
        left=Side(style='thin', color='E2E8F0'),
        right=Side(style='thin', color='E2E8F0'),
        top=Side(style='thin', color='E2E8F0'),
        bottom=Side(style='thin', color='E2E8F0')
    )

    align_center = Alignment(horizontal='center', vertical='center')
    align_left = Alignment(horizontal='left', vertical='center')
    align_right = Alignment(horizontal='right', vertical='center')

    # =========================================================================
    # SHEET 1: EXECUTIVE SUMMARY
    # =========================================================================
    ws_summary = wb.active
    ws_summary.title = "Executive Summary"
    ws_summary.views.sheetView[0].showGridLines = True

    # Title Banner
    ws_summary.merge_cells("A1:G2")
    ws_summary["A1"] = "CLOAKWATCH: MULTI-PROFILE THREAT MEASUREMENT REPORT"
    ws_summary["A1"].font = font_title
    ws_summary["A1"].fill = fill_navy
    ws_summary["A1"].alignment = align_center

    timestamp = scan_meta.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")) if scan_meta else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    total_targets = len(scan_results)
    malicious_count = sum(1 for r in scan_results if r.get("is_bad", False))
    clean_count = total_targets - malicious_count
    avg_score = round(sum(r.get("composite_score", 0.0) for r in scan_results) / max(1, total_targets), 1)

    ws_summary["A4"] = "Scan Metadata & Telemetry"
    ws_summary["A4"].font = font_section
    
    metadata_rows = [
        ("Scan Execution Timestamp", timestamp),
        ("Total Monitored Endpoints", total_targets),
        ("Confirmed Malicious / Cloaked", malicious_count),
        ("Benign / Clean Controls", clean_count),
        ("Average CloakScore", f"{avg_score} / 100"),
        ("Probing Mode", scan_meta.get("mode", "Multi-Persona Probing (P1-P4)") if scan_meta else "Standard")
    ]

    for idx, (k, v) in enumerate(metadata_rows, start=5):
        ws_summary[f"A{idx}"] = k
        ws_summary[f"A{idx}"].font = font_bold
        ws_summary[f"B{idx}"] = v
        ws_summary[f"B{idx}"].font = font_regular
        ws_summary[f"A{idx}"].border = thin_border
        ws_summary[f"B{idx}"].border = thin_border

    # Risk Band Guidance
    ws_summary["D4"] = "CloakScore Risk Classification Standard"
    ws_summary["D4"].font = font_section

    bands = [
        ("75.0 - 100.0", "CRITICAL_MALICIOUS", "Confirmed Cloaked SEO Spam / Doorway Delivery", "RED / BAD"),
        ("50.0 - 74.9", "SUSPICIOUS_HIGH", "Conditional Redirection / Stealth Injection", "ORANGE / BAD"),
        ("25.0 - 49.9", "ANOMALOUS_MEDIUM", "Unusual Dynamic Content / Header Drift", "YELLOW / CAUTION"),
        ("0.0 - 24.9", "BENIGN_SAFE", "Clean Static or Responsive Content", "GREEN / SAFE")
    ]

    headers_bands = ["Score Range", "Severity Code", "Operational Meaning", "Verdict"]
    for col_idx, h in enumerate(headers_bands, start=4):
        cell = ws_summary.cell(row=5, column=col_idx, value=h)
        cell.font = font_header
        cell.fill = fill_sub_header
        cell.alignment = align_center
        cell.border = thin_border

    for row_idx, band in enumerate(bands, start=6):
        for col_idx, val in enumerate(band, start=4):
            cell = ws_summary.cell(row=row_idx, column=col_idx, value=val)
            cell.font = font_regular
            cell.border = thin_border
            if col_idx == 7:
                cell.font = font_malicious if "BAD" in val else font_safe
                cell.fill = fill_malicious if "BAD" in val else fill_safe
                cell.alignment = align_center

    # =========================================================================
    # SHEET 2: THREAT ASSESSMENTS
    # =========================================================================
    ws_assess = wb.create_sheet(title="Threat Assessments")
    ws_assess.views.sheetView[0].showGridLines = True

    assess_headers = [
        "Target URL", "Domain", "Threat Score (0-100)", "Verdict", "Classification", 
        "Detected Campaign", "Semantic Score (25%)", "Routing Score (20%)", 
        "Payload Score (20%)", "Visual Score (20%)", "Transport Score (15%)", "Key Evidence & Telemetry"
    ]

    for col_idx, h in enumerate(assess_headers, start=1):
        cell = ws_assess.cell(row=1, column=col_idx, value=h)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center
        cell.border = thin_border

    for row_idx, r in enumerate(scan_results, start=2):
        score = r.get("composite_score", 0.0)
        is_bad = r.get("is_bad", False)
        verdict = "MALICIOUS" if is_bad else "BENIGN"
        breakdown = r.get("breakdown", {})

        row_data = [
            r.get("url", ""),
            r.get("domain", ""),
            score,
            verdict,
            r.get("verdict", ""),
            r.get("campaign", "None"),
            breakdown.get("semantic_divergence", {}).get("score", 0.0),
            breakdown.get("routing_divergence", {}).get("score", 0.0),
            breakdown.get("payload_signature", {}).get("score", 0.0),
            breakdown.get("structural_visual", {}).get("score", 0.0),
            breakdown.get("transport_entropy", {}).get("score", 0.0),
            r.get("description", "")
        ]

        for col_idx, val in enumerate(row_data, start=1):
            cell = ws_assess.cell(row=row_idx, column=col_idx, value=val)
            cell.font = font_regular
            cell.border = thin_border
            
            # Formatting
            if col_idx in [3, 7, 8, 9, 10, 11]:
                cell.alignment = align_right
                cell.number_format = '0.0'
            elif col_idx in [4, 5]:
                cell.alignment = align_center
                if col_idx == 4:
                    cell.font = font_malicious if is_bad else font_safe
                    cell.fill = fill_malicious if is_bad else fill_safe
            else:
                cell.alignment = align_left

            if row_idx % 2 == 1 and col_idx != 4:
                cell.fill = fill_zebra

    # =========================================================================
    # SHEET 3: DIFFERENTIAL ANALYSIS
    # =========================================================================
    ws_diff = wb.create_sheet(title="Differential Analysis")
    ws_diff.views.sheetView[0].showGridLines = True

    diff_headers = [
        "Target URL", "Comparison Type", "Status Divergence", "Redirect Divergence", 
        "HTML Cosine Sim (0-1)", "HTML Jaccard Sim (0-1)", "DOM Tree Edit Distance", 
        "Visual SSIM (0-1)", "pHash Distance", "Header Distance Score"
    ]

    for col_idx, h in enumerate(diff_headers, start=1):
        cell = ws_diff.cell(row=1, column=col_idx, value=h)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center
        cell.border = thin_border

    curr_diff_row = 2
    for r in scan_results:
        diffs = r.get("differential_pairs", [])
        url = r.get("url", "")
        for d in diffs:
            row_data = [
                url,
                d.get("comparison_type", "desktop_vs_crawler"),
                "YES" if d.get("status_code_divergence") else "NO",
                "YES" if d.get("redirect_divergence") else "NO",
                d.get("html_cosine_similarity", 1.0),
                d.get("html_jaccard_similarity", 1.0),
                d.get("dom_tree_edit_distance", 0),
                d.get("visual_ssim", 1.0),
                d.get("phash_hamming_distance", 0),
                d.get("header_distance_score", 0.0)
            ]
            for col_idx, val in enumerate(row_data, start=1):
                cell = ws_diff.cell(row=curr_diff_row, column=col_idx, value=val)
                cell.font = font_regular
                cell.border = thin_border
                if col_idx in [5, 6, 8, 10]:
                    cell.alignment = align_right
                    cell.number_format = '0.00'
                elif col_idx in [3, 4, 7, 9]:
                    cell.alignment = align_center
                else:
                    cell.alignment = align_left
            curr_diff_row += 1

    # =========================================================================
    # SHEET 4: RAW PROBE TELEMETRY
    # =========================================================================
    ws_raw = wb.create_sheet(title="Raw Probe Telemetry")
    ws_raw.views.sheetView[0].showGridLines = True

    raw_headers = [
        "Target URL", "Profile Label", "HTTP Status", "Final Resolved URL", 
        "Redirect Hops", "Body Size (Bytes)", "Response Time (ms)", 
        "Page Title", "Token Count", "Spam Category"
    ]

    for col_idx, h in enumerate(raw_headers, start=1):
        cell = ws_raw.cell(row=1, column=col_idx, value=h)
        cell.font = font_header
        cell.fill = fill_header
        cell.alignment = align_center
        cell.border = thin_border

    curr_raw_row = 2
    for r in scan_results:
        obs_list = r.get("observations", [])
        url = r.get("url", "")
        for obs in obs_list:
            row_data = [
                url,
                obs.get("profile_label", ""),
                obs.get("status_code", 0),
                obs.get("final_url", ""),
                obs.get("redirect_count", 0),
                obs.get("response_size_bytes", 0),
                obs.get("response_time_ms", 0),
                obs.get("page_title", ""),
                obs.get("text_token_count", 0),
                obs.get("injected_spam_category", "NONE")
            ]
            for col_idx, val in enumerate(row_data, start=1):
                cell = ws_raw.cell(row=curr_raw_row, column=col_idx, value=val)
                cell.font = font_regular
                cell.border = thin_border
                if col_idx in [3, 5, 6, 7, 9]:
                    cell.alignment = align_right
                elif col_idx in [2, 10]:
                    cell.alignment = align_center
                else:
                    cell.alignment = align_left
            curr_raw_row += 1

    # Auto-adjust column widths across all sheets
    for ws in [ws_summary, ws_assess, ws_diff, ws_raw]:
        for col in ws.columns:
            max_len = 0
            col_letter = get_column_letter(col[0].column)
            for cell in col:
                # ignore merged title banner in summary
                if ws == ws_summary and cell.row <= 2:
                    continue
                val_str = str(cell.value or '')
                max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(60, max(12, max_len + 3))

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)
    return output
