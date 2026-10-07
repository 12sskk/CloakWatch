#!/usr/bin/env python3
"""
CloakWatch: Longitudinal Study Query & Statistical Reporting Tool
Runs structured SQL queries against the 15-day differential measurement database
and prints publication-grade summary tables addressing Research Questions RQ1-RQ4.
"""

import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "cloakwatch_differential_study.db")

def print_separator(title=""):
    print("\n" + "=" * 95)
    if title:
        print(f"  {title.upper()}")
        print("=" * 95)

def run_query(conn, query, headers, col_widths=None):
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    if not col_widths:
        col_widths = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0)) + 2 for i, h in enumerate(headers)]

    header_str = " | ".join(f"{h:<{w}}" for h, w in zip(headers, col_widths))
    print(header_str)
    print("-" * len(header_str))

    for r in rows:
        row_str = " | ".join(f"{str(v):<{w}}" for v, w in zip(r, col_widths))
        print(row_str)
    print(f"Total Rows: {len(rows)}")

def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] Database not found at {DB_PATH}. Run generate_study_data.py first.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)

    print_separator("CloakWatch 15-Day Longitudinal Measurement Study: Research Dossier")
    print(f"Database: {DB_PATH}")

    # 1. High-Level Dataset Summary
    print_separator("1. Dataset Scope & Observation Telemetry")
    query_scope = """
        SELECT 
            COUNT(DISTINCT target_id) as total_targets,
            COUNT(DISTINCT day_index) as monitoring_days,
            COUNT(obs_id) as total_observations,
            COUNT(DISTINCT profile_label) as profiles_used,
            SUM(CASE WHEN injected_spam_category != 'NONE' THEN 1 ELSE 0 END) as compromised_payload_probes
        FROM observations
    """
    cursor = conn.cursor()
    cursor.execute(query_scope)
    scope = cursor.fetchone()
    print(f"  - Monitored Targets:            {scope[0]}")
    print(f"  - Longitudinal Window:          {scope[1]} Days (2026-09-15 to 2026-09-29)")
    print(f"  - Total Probe Observations:     {scope[2]} (4 distinct profiles per target per day)")
    print(f"  - Active Probing Profiles:      {scope[3]} (P1 Desktop, P2 Mobile, P3 Googlebot, P4 Mobile Bot)")
    print(f"  - Compromised Injections Found: {scope[4]} individual responses with confirmed spam payloads")

    # 2. RQ1: Target Summary & Campaign Taxonomy
    print_separator("2. RQ1: Target Classification & Cloaking Prevalence")
    query_targets = """
        SELECT 
            t.target_id,
            t.domain,
            t.category,
            ROUND(AVG(ce.cloak_score), 3) as avg_score,
            ROUND(MAX(ce.cloak_score), 3) as max_score,
            SUM(CASE WHEN ce.classification LIKE 'CLOAKED%' THEN 1 ELSE 0 END) as days_cloaked,
            GROUP_CONCAT(DISTINCT ce.detected_campaign) as campaigns
        FROM targets t
        JOIN cloaking_evaluations ce ON t.target_id = ce.target_id
        GROUP BY t.target_id
        ORDER BY days_cloaked DESC, avg_score DESC
    """
    run_query(conn, query_targets, 
              ["ID", "Domain", "Category", "Avg Score", "Peak Score", "Cloaked Days", "Detected Campaigns"],
              [4, 28, 22, 10, 11, 13, 30])

    # 3. RQ2: Cloaking Trigger Mechanisms
    print_separator("3. RQ2: Adversarial Delivery & Cloaking Trigger Mechanisms")
    query_mechanisms = """
        SELECT 
            primary_signal as cloaking_mechanism,
            COUNT(*) as observation_count,
            ROUND(AVG(cloak_score), 3) as mean_cloak_score,
            COUNT(DISTINCT target_id) as affected_targets
        FROM cloaking_evaluations
        GROUP BY primary_signal
        ORDER BY observation_count DESC
    """
    run_query(conn, query_mechanisms,
              ["Cloaking Mechanism / Trigger Signal", "Obs Count", "Mean Score", "Targets"],
              [60, 10, 12, 8])

    # 4. RQ3: Campaign Evolution Timeline (Selected Case Study)
    print_separator("4. RQ3: Temporal Campaign Evolution & Life-Cycle Case Studies")
    query_evolution = """
        SELECT 
            t.domain,
            ce.start_day || ' - ' || ce.end_day as days,
            (ce.end_day - ce.start_day + 1) as duration,
            ce.observed_state,
            ce.active_campaign,
            ce.transition_trigger
        FROM campaign_evolution ce
        JOIN targets t ON ce.target_id = t.target_id
        WHERE ce.target_id IN (1, 4, 9)
        ORDER BY t.target_id, ce.start_day
    """
    run_query(conn, query_evolution,
              ["Target Domain", "Days", "Span", "Observed State", "Campaign", "Transition Trigger"],
              [26, 8, 5, 25, 28, 40])

    # 5. RQ4: Methodological Validation (Separating Responsive Design from Cloaking)
    print_separator("5. RQ4: Methodological Validation: Cloaking vs Benign Responsive Controls")
    query_rq4 = """
        SELECT 
            CASE 
                WHEN t.category = 'BENIGN_CONTROL' THEN 'Benign Controls (Responsive & Static)'
                ELSE 'Compromised Target Domains'
            END as cohort,
            ROUND(AVG(dp.html_cosine_similarity), 3) as avg_html_cosine_sim,
            ROUND(AVG(dp.visual_ssim), 3) as avg_visual_ssim,
            ROUND(AVG(ce.cloak_score), 3) as avg_cloak_score,
            ROUND(MAX(ce.cloak_score), 3) as max_cloak_score
        FROM targets t
        JOIN cloaking_evaluations ce ON t.target_id = ce.target_id
        JOIN differential_pairs dp ON ce.run_id = dp.run_id AND ce.target_id = dp.target_id AND dp.comparison_type = 'desktop_vs_crawler'
        GROUP BY cohort
    """
    run_query(conn, query_rq4,
              ["Target Cohort", "Avg Cosine Sim", "Avg Visual SSIM", "Avg CloakScore", "Max CloakScore"],
              [38, 16, 17, 16, 16])

    print_separator("End of Research Dossier")
    conn.close()

if __name__ == "__main__":
    main()
