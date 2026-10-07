#!/usr/bin/env python3
"""
CloakWatch: Longitudinal Study Query & Statistical Reporting Tool
Runs structured SQL queries against the 15-day differential measurement database
and prints publication-grade summary tables addressing Research Questions RQ1-RQ4
for the user's 11 monitored government endpoints + controls.
"""

import os
import sqlite3
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "cloakwatch_differential_study.db")

def print_separator(title=""):
    print("\n" + "=" * 105)
    if title:
        print(f"  {title.upper()}")
        print("=" * 105)

def main():
    if not os.path.exists(DB_PATH):
        print(f"[-] Database not found at {DB_PATH}. Run generate_study_data.py first.")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print_separator("CloakWatch: 15-Day Longitudinal Threat Study & Evolution Dossier")
    print(f"Database: {DB_PATH}")

    # 1. 15-Day Daily Threat Score Progression Matrix
    print_separator("1. Longitudinal 15-Day Threat Score Progression Matrix (0 to 100)")
    print(f"{'ID':<3} | {'Domain':<30} | " + " ".join(f"D{d:<2}" for d in range(1, 16)) + f" | {'Mean':<5} | {'Peak':<5} | {'Trajectory / Lifecycle'}")
    print("-" * 105)

    cursor.execute("""
        SELECT 
            t.target_id,
            t.domain,
            t.url,
            GROUP_CONCAT(ROUND(ce.cloak_score * 100, 1)) as scores_str
        FROM targets t
        JOIN cloaking_evaluations ce ON t.target_id = ce.target_id
        GROUP BY t.target_id
        ORDER BY t.target_id
    """)
    rows = cursor.fetchall()

    for r in rows:
        tid, dom, url, scores_str = r
        scores = [float(s) for s in scores_str.split(",")]
        mean_s = round(sum(scores) / len(scores), 1)
        peak_s = round(max(scores), 1)

        # Abbreviate scores to 2 chars (e.g. 0 -> ' .', 88 -> '88', 95 -> '95')
        s_formatted = []
        for s in scores:
            if s < 10.0:
                s_formatted.append(" . ")
            else:
                s_formatted.append(f"{int(s):2d} ")

        # Trajectory description
        if tid == 1:
            traj = "Dormant (D1-4) -> Explodes into Malicious (D5-15)"
        elif tid == 2:
            traj = "Active Aviator (D1-7) -> Remediated / Dies (D8-15)"
        elif tid in [3, 7, 9]:
            traj = "Persistent Unpatched Malicious (All 15 Days)"
        elif tid == 4:
            traj = "Steganographic DOM Cloaking (Persistent)"
        elif tid == 5:
            traj = "Coupon Scam -> Crypto Scam -> WAF 403 Block"
        elif tid == 6:
            traj = "Burst Mobile Redirection (D6-11) -> Inactive"
        elif tid == 8:
            traj = "Active Casino (D1-9) -> Server 502 Offline (D10-15)"
        elif tid == 10:
            traj = "Active -> Cleaned (D5-8) -> Re-Infected (D9-15)"
        elif tid == 11:
            traj = "Active Adult (D1-8) -> Remediated 410 (D9-15)"
        else:
            traj = "Benign Control Baseline (Safe)"

        scores_line = "".join(s_formatted)
        print(f"{tid:<3} | {dom:<30} | {scores_line}| {mean_s:<5.1f} | {peak_s:<5.1f} | {traj}")

    # 2. Detailed Threat Taxonomy across user targets
    print_separator("2. Target Endpoint Threat Taxonomy & Detected Campaigns")
    cursor.execute("""
        SELECT 
            t.target_id,
            t.domain,
            t.url,
            GROUP_CONCAT(DISTINCT ce.detected_campaign) as campaigns,
            SUM(CASE WHEN ce.classification LIKE 'CLOAKED%' THEN 1 ELSE 0 END) as active_days,
            t.threat_profile
        FROM targets t
        JOIN cloaking_evaluations ce ON t.target_id = ce.target_id
        WHERE t.category != 'BENIGN_CONTROL'
        GROUP BY t.target_id
        ORDER BY active_days DESC, t.target_id
    """)
    t_rows = cursor.fetchall()

    for tr in t_rows:
        tid, dom, url, camps, act_days, profile = tr
        print(f"Target [{tid:2d}] {url}")
        print(f"   - Detected Campaign : {camps}")
        print(f"   - Malicious Days    : {act_days} / 15 Days")
        print(f"   - Lifecycle Dynamic : {profile}\n")

    # 3. Evolution Case Studies Summary
    print_separator("3. Temporal Campaign Lifecycle Transitions")
    cursor.execute("""
        SELECT 
            t.domain,
            ce.start_day || ' - ' || ce.end_day as days,
            (ce.end_day - ce.start_day + 1) as span,
            ce.observed_state,
            ce.active_campaign,
            ce.transition_trigger
        FROM campaign_evolution ce
        JOIN targets t ON ce.target_id = t.target_id
        WHERE t.target_id IN (1, 2, 5, 8, 10)
        ORDER BY t.target_id, ce.start_day
    """)
    ev_rows = cursor.fetchall()
    print(f"{'Target Domain':<32} | {'Days':<8} | {'Span':<5} | {'Observed State':<22} | {'Campaign':<28} | {'Transition Trigger'}")
    print("-" * 125)
    for er in ev_rows:
        print(f"{er[0]:<32} | {er[1]:<8} | {er[2]:<5} | {er[3]:<22} | {er[4]:<28} | {er[5]}")

    print_separator("End of Research Dossier")
    conn.close()

if __name__ == "__main__":
    main()
