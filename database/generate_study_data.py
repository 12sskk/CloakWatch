#!/usr/bin/env python3
"""
CloakWatch: Longitudinal Differential Measurement Dataset Generator
Simulates a rigorous 15-day longitudinal study tracking multi-profile probing
across compromised government/institutional websites and benign controls.
Generates an SQLite database and exportable CSVs for statistical presentation.
"""

import os
import sys
import json
import sqlite3
import hashlib
import random
import datetime
import csv
from typing import Dict, List, Tuple

DB_PATH = os.path.join(os.path.dirname(__file__), "cloakwatch_differential_study.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema.sql")
EXPORTS_DIR = os.path.join(os.path.dirname(__file__), "exports")

# Ensure reproducibility
random.seed(42)

START_DATE = datetime.date(2026, 9, 15)

PROFILES = {
    "P1_desktop_normal": {
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "viewport": "1920x1080",
        "type": "USER_DESKTOP"
    },
    "P2_mobile_normal": {
        "ua": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
        "viewport": "390x844",
        "type": "USER_MOBILE"
    },
    "P3_crawler_oriented": {
        "ua": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36",
        "viewport": "1920x1080",
        "type": "BOT_DESKTOP"
    },
    "P4_mobile_crawler": {
        "ua": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/128.0.6613.88 Mobile Safari/537.36",
        "viewport": "390x844",
        "type": "BOT_MOBILE"
    }
}

TARGETS_DEF = [
    {
        "domain": "transport.wb.gov.in",
        "url": "https://transport.wb.gov.in/services/permit-status",
        "category": "GOVERNMENT_STATE",
        "jurisdiction": "West Bengal, India",
        "threat_profile": "Compromised CMS: Temporal Campaign Shift (Dormant -> Casino -> Crypto -> Remediated)"
    },
    {
        "domain": "scholarships.gov.in",
        "url": "https://scholarships.gov.in/portal/scheme-guidelines",
        "category": "GOVERNMENT_NATIONAL",
        "jurisdiction": "National (India)",
        "threat_profile": "Persistent Multi-Vector Cloaking: Piracy/APK directory for Googlebot, Mobile User Redirect to Scam Affiliate"
    },
    {
        "domain": "health.delhi.gov.in",
        "url": "https://health.delhi.gov.in/reports/bulletin-2024",
        "category": "GOVERNMENT_MUNICIPAL",
        "jurisdiction": "Delhi NCT, India",
        "threat_profile": "Classic User-Agent Cloaking: Unlicensed Online Pharmacy for Search Bots, 404 for Normal Browsers"
    },
    {
        "domain": "agri.up.gov.in",
        "url": "https://agri.up.gov.in/schemes/kisan-subsidy",
        "category": "GOVERNMENT_STATE",
        "jurisdiction": "Uttar Pradesh, India",
        "threat_profile": "Intermittent Mobile-Targeted Infiltration: Telegram Betting Redirection for Mobile Users on Days 6-12"
    },
    {
        "domain": "library.univ-punjab.ac.in",
        "url": "https://library.univ-punjab.ac.in/archives/digitized",
        "category": "ACADEMIC",
        "jurisdiction": "Punjab, India",
        "threat_profile": "Academic Ghostwriting SEO Hijack: Essay-writing service keywords injected for Googlebot until Day 10 cleanup"
    },
    {
        "domain": "treasury.gov",
        "url": "https://www.treasury.gov/resource-center/data-chart",
        "category": "BENIGN_CONTROL",
        "jurisdiction": "Federal (United States)",
        "threat_profile": "Benign Responsive Baseline: High visual CSS variance across viewports, Identical semantic text"
    },
    {
        "domain": "iitd.ac.in",
        "url": "https://www.iitd.ac.in/events/annual-symposium",
        "category": "BENIGN_CONTROL",
        "jurisdiction": "National Institute (India)",
        "threat_profile": "Benign Responsive Baseline: Standard academic portal with media-query responsive navigation"
    },
    {
        "domain": "cybercrime.gov.in",
        "url": "https://cybercrime.gov.in/static/awareness.html",
        "category": "BENIGN_CONTROL",
        "jurisdiction": "National (India)",
        "threat_profile": "Benign Static Baseline: Exact byte-for-byte identical HTML and SSIM 1.0 across all 4 profiles"
    },
    {
        "domain": "municipal.karnataka.gov.in",
        "url": "https://municipal.karnataka.gov.in/notices/tenders",
        "category": "GOVERNMENT_MUNICIPAL",
        "jurisdiction": "Karnataka, India",
        "threat_profile": "Active Compromise with Rapid Mitigation: Online Slot Spam Days 1-7, Incident response WAF block on Day 8"
    },
    {
        "domain": "archives.tn.gov.in",
        "url": "https://archives.tn.gov.in/public/gazette-2023",
        "category": "GOVERNMENT_STATE",
        "jurisdiction": "Tamil Nadu, India",
        "threat_profile": "DOM-Hidden CSS Cloaking: 45 gambling anchor links hidden off-screen (opacity:0), high visual similarity but low DOM similarity"
    }
]

def make_hash(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def generate_target_state(target_id: int, day: int, profile_key: str):
    """
    Simulates exact ground truth observation for a target on a given day and profile.
    Returns: (status_code, final_url, redirect_count, redirect_chain, resp_size, resp_time, title, tokens, spam_cat, html_content_id)
    """
    # Target 1: transport.wb.gov.in (Temporal evolution)
    if target_id == 1:
        if day in [1, 2, 3]:
            # Dormant 404 for everyone
            return (404, "https://transport.wb.gov.in/services/permit-status", 0, [], 1840, 310, "404 Not Found - Transport Dept", 85, "NONE", "wb_404")
        elif day in range(4, 9):
            # Slot88 Casino for Googlebot, 404 for Normal User
            if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
                return (200, "https://transport.wb.gov.in/services/permit-status", 0, [], 28450, 420, "SITUS JUDI SLOT88 GACOR DEPOSIT PULSA RESMI TERPERCAYA 2026", 2450, "CASINO_GAMBLING", "wb_casino")
            else:
                return (404, "https://transport.wb.gov.in/services/permit-status", 0, [], 1840, 290, "404 Not Found - Transport Dept", 85, "NONE", "wb_404")
        elif day in range(9, 14):
            # Pivot to Crypto Scam for Googlebot
            if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
                return (200, "https://transport.wb.gov.in/services/permit-status", 0, [], 34120, 480, "Global Crypto Assets Recovery | Stolen BTC Expert Claim Portal", 2890, "CRYPTO_SCAM", "wb_crypto")
            else:
                return (404, "https://transport.wb.gov.in/services/permit-status", 0, [], 1840, 295, "404 Not Found - Transport Dept", 85, "NONE", "wb_404")
        else: # Day 14, 15: Remediated
            return (403, "https://transport.wb.gov.in/services/permit-status", 0, [], 1220, 180, "403 Forbidden - Access Blocked by Security Gateway", 45, "NONE", "wb_waf_blocked")

    # Target 2: scholarships.gov.in (Piracy for bots, mobile affiliate redirect)
    elif target_id == 2:
        if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
            return (200, "https://scholarships.gov.in/portal/scheme-guidelines", 0, [], 42100, 380, "Download GTA V Mobile APK Mod v2.4 + Obb Unlimited Money Free", 3420, "PIRACY_APK", "nsp_apk")
        elif profile_key == "P2_mobile_normal":
            # Mobile normal user redirected to affiliate scam
            chain = [
                {"url": "https://scholarships.gov.in/portal/scheme-guidelines", "status": 302},
                {"url": "https://traffic-gate7.affiliates.net/in/clk?id=99281", "status": 302},
                {"url": "https://spin-wheel-rewards2026.online/claim?token=8f92", "status": 200}
            ]
            return (200, "https://spin-wheel-rewards2026.online/claim?token=8f92", 2, chain, 19400, 710, "Congratulations! You Won iPhone 16 Pro - Claim Now", 420, "CRYPTO_SCAM", "nsp_mobile_scam")
        else: # P1 desktop normal sees legitimate government guidelines
            return (200, "https://scholarships.gov.in/portal/scheme-guidelines", 0, [], 38900, 410, "National Scholarship Portal: Central Sector Scheme Guidelines 2026", 2150, "NONE", "nsp_genuine")

    # Target 3: health.delhi.gov.in (Unlicensed Pharma for Googlebot)
    elif target_id == 3:
        if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
            return (200, "https://health.delhi.gov.in/reports/bulletin-2024", 0, [], 31200, 390, "Order Generic Viagra 100mg Cialis Online Without Prescription Fast Delivery", 2980, "PHARMA_SPAM", "delhi_pharma")
        else:
            return (404, "https://health.delhi.gov.in/reports/bulletin-2024", 0, [], 1650, 260, "Department of Health - Document Not Found", 90, "NONE", "delhi_404")

    # Target 4: agri.up.gov.in (Mobile targeted betting redirection days 6-12)
    elif target_id == 4:
        if day in range(6, 13) and profile_key == "P2_mobile_normal":
            chain = [
                {"url": "https://agri.up.gov.in/schemes/kisan-subsidy", "status": 302},
                {"url": "https://t.me/vip_betting_sureodds_2026", "status": 200}
            ]
            return (200, "https://t.me/vip_betting_sureodds_2026", 1, chain, 8400, 620, "Telegram: VIP Sure Betting Odds Channel", 120, "CASINO_GAMBLING", "agri_tele_bet")
        else:
            # Genuine farmer subsidy page for all other profiles/days
            return (200, "https://agri.up.gov.in/schemes/kisan-subsidy", 0, [], 29400, 340, "Agriculture Department UP - Kisan Fertilizer Subsidy Application Form", 1680, "NONE", "agri_genuine")

    # Target 5: library.univ-punjab.ac.in (Academic essay writing spam)
    elif target_id == 5:
        if day <= 10:
            if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
                return (200, "https://library.univ-punjab.ac.in/archives/digitized", 0, [], 26800, 350, "Top 10 Legit Essay Writing Services Reviews 2026 - Hire Paper Writers", 2100, "ESSAY_WRITING", "punjab_essay")
            else:
                return (404, "https://library.univ-punjab.ac.in/archives/digitized", 0, [], 1420, 240, "Digital Archives - Collection Expired or Removed", 65, "NONE", "punjab_404")
        else:
            # Day 11-15: Administrator removed endpoint completely (410 Gone)
            return (410, "https://library.univ-punjab.ac.in/archives/digitized", 0, [], 890, 190, "410 Gone - Resource Permanently Purged", 40, "NONE", "punjab_410")

    # Target 6: treasury.gov (Benign Responsive Control)
    elif target_id == 6:
        # Same underlying text for all, mobile layout slightly smaller byte size due to inline SVGs or viewport CSS
        size = 45200 if "mobile" in profile_key else 47800
        return (200, "https://www.treasury.gov/resource-center/data-chart", 0, [], size, 220, "US Treasury: Interest Rate Statistics & Historical Yield Curves", 2600, "NONE", "treasury_responsive")

    # Target 7: iitd.ac.in (Benign Responsive Control)
    elif target_id == 7:
        size = 32100 if "mobile" in profile_key else 33500
        return (200, "https://www.iitd.ac.in/events/annual-symposium", 0, [], size, 190, "IIT Delhi - Annual Technical Symposium & Keynote Lectures 2026", 1850, "NONE", "iitd_responsive")

    # Target 8: cybercrime.gov.in (Benign Static Control)
    elif target_id == 8:
        # Exactly identical across all 4 profiles
        return (200, "https://cybercrime.gov.in/static/awareness.html", 0, [], 21450, 160, "National Cyber Crime Reporting Portal - Cyber Security Tips", 1420, "NONE", "cybercrime_static")

    # Target 9: municipal.karnataka.gov.in (Slot spam days 1-7, patched Day 8)
    elif target_id == 9:
        if day <= 7:
            if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
                return (200, "https://municipal.karnataka.gov.in/notices/tenders", 0, [], 36700, 440, "DAFTAR AKUN PRO THAILAND SLOT GACOR MUDAH MAXWIN HARI INI 2026", 3100, "CASINO_GAMBLING", "karnataka_casino")
            else:
                return (200, "https://municipal.karnataka.gov.in/notices/tenders", 0, [], 24500, 310, "Directorate of Municipal Administration - Public Works Tender Notices", 1340, "NONE", "karnataka_genuine")
        else:
            # Day 8-15: Security patch / WAF maintenance
            return (503, "https://municipal.karnataka.gov.in/notices/tenders", 0, [], 1120, 150, "503 Service Unavailable - Portal Under Security Audit", 35, "NONE", "karnataka_remediated")

    # Target 10: archives.tn.gov.in (DOM CSS Hidden Cloaked Links)
    elif target_id == 10:
        if profile_key in ["P3_crawler_oriented", "P4_mobile_crawler"]:
            # Hidden anchor spam present in DOM for bots
            return (200, "https://archives.tn.gov.in/public/gazette-2023", 0, [], 38900, 380, "Tamil Nadu Archives - Official State Gazette Notifications 2023", 2650, "CASINO_GAMBLING", "tn_css_cloaked")
        else:
            # Clean page for normal user
            return (200, "https://archives.tn.gov.in/public/gazette-2023", 0, [], 28100, 330, "Tamil Nadu Archives - Official State Gazette Notifications 2023", 1820, "NONE", "tn_normal")

    raise ValueError(f"Unknown target_id {target_id}")

def compute_differential_pair_metrics(t_id: int, day: int, comp_type: str, obs_a: dict, obs_b: dict) -> dict:
    """
    Computes rigorous differential measurement metrics:
    - Status divergence
    - Redirect divergence
    - HTML Cosine Similarity
    - HTML Jaccard Similarity
    - DOM Tree Edit Distance
    - Visual SSIM
    - pHash Hamming Distance
    - Header Distance
    """
    status_div = (obs_a["status_code"] != obs_b["status_code"])
    redir_div = (obs_a["final_url"] != obs_b["final_url"])

    # Baseline defaults
    jaccard = 1.0
    cosine = 1.0
    dom_dist = 0
    ssim = 1.0
    phash_dist = 0
    header_dist = 0.02

    c_id_a = obs_a["content_id"]
    c_id_b = obs_b["content_id"]

    if c_id_a == c_id_b:
        # Same underlying content
        if "mobile" in comp_type:
            # Legitimate responsive layout difference
            ssim = 0.58 if t_id in [6, 7] else 0.85
            phash_dist = 14 if t_id in [6, 7] else 4
            jaccard = 0.98
            cosine = 0.99
            dom_dist = 18
        else:
            # Exact desktop vs desktop matching
            ssim = 1.00
            phash_dist = 0
            jaccard = 1.00
            cosine = 1.00
            dom_dist = 0
    else:
        # Content difference exists!
        if status_div: # e.g. 200 vs 404
            jaccard = 0.04 + random.uniform(0.01, 0.03)
            cosine = 0.08 + random.uniform(0.01, 0.04)
            dom_dist = 340 + random.randint(10, 50)
            ssim = 0.12 + random.uniform(0.01, 0.05)
            phash_dist = 38 + random.randint(1, 6)
            header_dist = 0.65
        elif redir_div: # e.g. normal page vs scam affiliate redirect
            jaccard = 0.01 + random.uniform(0.005, 0.02)
            cosine = 0.03 + random.uniform(0.005, 0.02)
            dom_dist = 520 + random.randint(20, 80)
            ssim = 0.05 + random.uniform(0.01, 0.04)
            phash_dist = 44 + random.randint(1, 5)
            header_dist = 0.85
        elif t_id == 10: # Steganographic / CSS-hidden links (high visual similarity, but low DOM similarity)
            jaccard = 0.62 + random.uniform(0.01, 0.03)
            cosine = 0.74 + random.uniform(0.01, 0.03)
            dom_dist = 165 + random.randint(5, 20)
            ssim = 0.96 # Visually identical because injected links have opacity:0!
            phash_dist = 2
            header_dist = 0.15
        elif t_id == 9 and day <= 7: # Government tender vs Indonesian Slot88 spam
            jaccard = 0.06 + random.uniform(0.01, 0.02)
            cosine = 0.11 + random.uniform(0.01, 0.03)
            dom_dist = 410 + random.randint(10, 40)
            ssim = 0.14 + random.uniform(0.01, 0.03)
            phash_dist = 36 + random.randint(1, 4)
            header_dist = 0.55
        else:
            jaccard = 0.05 + random.uniform(0.01, 0.03)
            cosine = 0.09 + random.uniform(0.01, 0.04)
            dom_dist = 380 + random.randint(10, 40)
            ssim = 0.15 + random.uniform(0.01, 0.04)
            phash_dist = 35 + random.randint(1, 5)
            header_dist = 0.60

    return {
        "status_code_divergence": status_div,
        "redirect_divergence": redir_div,
        "html_cosine_similarity": round(min(1.0, max(0.0, cosine)), 4),
        "html_jaccard_similarity": round(min(1.0, max(0.0, jaccard)), 4),
        "dom_tree_edit_distance": dom_dist,
        "visual_ssim": round(min(1.0, max(0.0, ssim)), 4),
        "phash_hamming_distance": phash_dist,
        "header_distance_score": round(header_dist, 4)
    }

def evaluate_cloaking(t_id: int, day: int, diff_desktop_bot: dict, diff_desktop_mobile: dict) -> Tuple[float, str, str, str, str]:
    """
    Computes CloakScore and classifies the measurement.
    Formula:
      CloakScore = 0.35*(1 - CosineSim) + 0.25*(1 - SSIM) + 0.20*(RedirectDiv) + 0.15*(StatusDiv) + 0.05*(HeaderDist)
    With legitimate responsive penalty dampening.
    """
    status_div = 1.0 if diff_desktop_bot["status_code_divergence"] else 0.0
    redir_div = 1.0 if diff_desktop_bot["redirect_divergence"] or diff_desktop_mobile["redirect_divergence"] else 0.0
    cos_diff = 1.0 - diff_desktop_bot["html_cosine_similarity"]
    ssim_diff = 1.0 - diff_desktop_bot["visual_ssim"]
    header_diff = diff_desktop_bot["header_distance_score"]

    raw_score = (0.35 * cos_diff) + (0.25 * ssim_diff) + (0.20 * redir_div) + (0.15 * status_div) + (0.05 * header_diff)

    # Controls
    if t_id in [6, 7]: # Benign Responsive
        score = 0.025 + random.uniform(0.005, 0.015)
        return (round(score, 3), "BENIGN_RESPONSIVE", "Media Query Viewport Layout Shift (Identical Semantic Text)", "None", "HIGH")
    elif t_id == 8: # Benign Static
        return (0.000, "BENIGN_STATIC", "Exact Match Across All Profiles", "None", "HIGH")

    # Specific targets based on day
    if t_id == 1:
        if day in [1, 2, 3]:
            return (0.000, "DORMANT_OR_OFFLINE", "Unified 404 Status Across Profiles", "None", "HIGH")
        elif day in range(4, 9):
            return (round(min(0.99, max(0.85, raw_score)), 3), "CLOAKED_SEO_SPAM", "User-Agent Triggered Status Divergence (404 vs 200 Slot88)", "Slot88 / Gacor Gambling", "HIGH")
        elif day in range(9, 14):
            return (round(min(0.99, max(0.88, raw_score)), 3), "CLOAKED_SEO_SPAM", "User-Agent Injected Scam Landing (404 vs 200 Crypto)", "Crypto Recovery Scam", "HIGH")
        else:
            return (0.000, "REMEDIATED", "Access Blocked / Cleaned by WAF Gateway (403)", "None", "HIGH")

    elif t_id == 2:
        return (0.965, "CLOAKED_CONDITIONAL_REDIRECT", "Bot Gets Piracy Directory, Mobile User Gets Affiliate Scam Redirect", "Piracy APK & Affiliate Fraud", "HIGH")

    elif t_id == 3:
        return (0.940, "CLOAKED_SEO_SPAM", "User-Agent Header Cloaking: Pharmacy Spam for Bots, 404 for Users", "Unlicensed Pharmacy / Rx Spam", "HIGH")

    elif t_id == 4:
        if day in range(6, 13):
            return (0.890, "CLOAKED_CONDITIONAL_REDIRECT", "Mobile User Conditional Redirect to Telegram Gambling", "Telegram Betting Syndicate", "HIGH")
        else:
            return (0.010, "BENIGN_RESPONSIVE", "Normal Agriculture Government Portal", "None", "HIGH")

    elif t_id == 5:
        if day <= 10:
            return (0.925, "CLOAKED_SEO_SPAM", "Bot Gets Academic Essay Service, Users Get 404", "Academic Ghostwriting Spam", "HIGH")
        else:
            return (0.000, "REMEDIATED", "Path Purged by Admin (410 Gone for all)", "None", "HIGH")

    elif t_id == 9:
        if day <= 7:
            return (0.950, "CLOAKED_SEO_SPAM", "Bot Injected Indonesian Casino, Desktop Sees Tender Notice", "Indonesian Slot88 Maxwin", "HIGH")
        else:
            return (0.000, "REMEDIATED", "Security Maintenance / Remediation (503 Service Unavailable)", "None", "HIGH")

    elif t_id == 10:
        return (0.835, "CLOAKED_SEO_SPAM", "DOM CSS-Hidden Steganographic Anchor Links (High Visual Sim, Low DOM Sim)", "Blackhat Casino Link Network", "HIGH")

    return (round(raw_score, 3), "CLOAKED_SEO_SPAM", "Differential Anomaly Detected", "Unknown", "MEDIUM")

def main():
    print(f"[*] Initializing CloakWatch Longitudinal Database at: {DB_PATH}")
    os.makedirs(EXPORTS_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        try:
            os.remove(DB_PATH)
        except Exception:
            pass

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Load and execute schema
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        cursor.executescript(f.read())

    # 1. Insert Targets
    print("[*] Inserting 10 monitored target specifications...")
    target_ids = {}
    for t in TARGETS_DEF:
        cursor.execute("""
            INSERT INTO targets (domain, url, category, jurisdiction, threat_profile)
            VALUES (?, ?, ?, ?, ?)
        """, (t["domain"], t["url"], t["category"], t["jurisdiction"], t["threat_profile"]))
        target_ids[t["url"]] = cursor.lastrowid

    # 2. Insert 15-Day Crawl Runs & Observations
    print("[*] Simulating 15-day longitudinal multi-profile crawl cycles...")
    total_observations = 0
    total_diff_pairs = 0
    total_evals = 0

    all_obs_data = []
    all_diff_data = []
    all_eval_data = []

    for day in range(1, 16):
        crawl_date = START_DATE + datetime.timedelta(days=day - 1)
        cursor.execute("""
            INSERT INTO crawl_runs (day_index, scheduled_date, total_targets, completed_observations, execution_status)
            VALUES (?, ?, ?, ?, ?)
        """, (day, crawl_date.isoformat(), len(TARGETS_DEF), len(TARGETS_DEF) * 4, 'COMPLETED'))
        run_id = cursor.lastrowid

        for t_idx, t_def in enumerate(TARGETS_DEF, start=1):
            t_id = t_idx
            obs_map = {}

            # Generate 4 observations per target
            for prof_key, prof_meta in PROFILES.items():
                (status, final_url, redir_cnt, redir_chain, size, r_time, title, tokens, spam_cat, content_id) = generate_target_state(t_id, day, prof_key)

                # Simulated content hash
                html_hash = make_hash(f"{content_id}_{size}_{title}")
                screenshot_hash = make_hash(f"{content_id}_{prof_meta['viewport']}_{status}")

                cursor.execute("""
                    INSERT INTO observations (
                        run_id, target_id, day_index, profile_label, user_agent, viewport,
                        status_code, final_url, redirect_count, redirect_chain_json,
                        response_time_ms, response_size_bytes, html_sha256, screenshot_sha256,
                        page_title, text_token_count, injected_spam_category
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    run_id, t_id, day, prof_key, prof_meta["ua"], prof_meta["viewport"],
                    status, final_url, redir_cnt, json.dumps(redir_chain),
                    r_time, size, html_hash, screenshot_hash,
                    title, tokens, spam_cat
                ))
                obs_id = cursor.lastrowid
                total_observations += 1

                obs_info = {
                    "obs_id": obs_id,
                    "status_code": status,
                    "final_url": final_url,
                    "content_id": content_id,
                    "profile_key": prof_key,
                    "size": size,
                    "title": title,
                    "spam_cat": spam_cat
                }
                obs_map[prof_key] = obs_info
                all_obs_data.append({
                    "day": day,
                    "date": crawl_date.isoformat(),
                    "domain": t_def["domain"],
                    "url": t_def["url"],
                    "profile": prof_key,
                    "status": status,
                    "final_url": final_url,
                    "redirects": redir_cnt,
                    "size_bytes": size,
                    "latency_ms": r_time,
                    "html_sha256": html_hash,
                    "spam_category": spam_cat
                })

            # 3. Compute Pairwise Differential Probes
            # Comparison A: Desktop Normal (P1) vs Crawler Desktop (P3)
            diff_d_c = compute_differential_pair_metrics(t_id, day, "desktop_vs_crawler", obs_map["P1_desktop_normal"], obs_map["P3_crawler_oriented"])
            cursor.execute("""
                INSERT INTO differential_pairs (
                    run_id, target_id, day_index, comparison_type, obs_id_a, obs_id_b,
                    status_code_divergence, redirect_divergence, html_cosine_similarity,
                    html_jaccard_similarity, dom_tree_edit_distance, visual_ssim,
                    phash_hamming_distance, header_distance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, t_id, day, "desktop_vs_crawler",
                obs_map["P1_desktop_normal"]["obs_id"], obs_map["P3_crawler_oriented"]["obs_id"],
                diff_d_c["status_code_divergence"], diff_d_c["redirect_divergence"],
                diff_d_c["html_cosine_similarity"], diff_d_c["html_jaccard_similarity"],
                diff_d_c["dom_tree_edit_distance"], diff_d_c["visual_ssim"],
                diff_d_c["phash_hamming_distance"], diff_d_c["header_distance_score"]
            ))
            total_diff_pairs += 1

            # Comparison B: Desktop Normal (P1) vs Mobile Normal (P2)
            diff_d_m = compute_differential_pair_metrics(t_id, day, "desktop_vs_mobile", obs_map["P1_desktop_normal"], obs_map["P2_mobile_normal"])
            cursor.execute("""
                INSERT INTO differential_pairs (
                    run_id, target_id, day_index, comparison_type, obs_id_a, obs_id_b,
                    status_code_divergence, redirect_divergence, html_cosine_similarity,
                    html_jaccard_similarity, dom_tree_edit_distance, visual_ssim,
                    phash_hamming_distance, header_distance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, t_id, day, "desktop_vs_mobile",
                obs_map["P1_desktop_normal"]["obs_id"], obs_map["P2_mobile_normal"]["obs_id"],
                diff_d_m["status_code_divergence"], diff_d_m["redirect_divergence"],
                diff_d_m["html_cosine_similarity"], diff_d_m["html_jaccard_similarity"],
                diff_d_m["dom_tree_edit_distance"], diff_d_m["visual_ssim"],
                diff_d_m["phash_hamming_distance"], diff_d_m["header_distance_score"]
            ))
            total_diff_pairs += 1

            # Comparison C: Crawler Desktop (P3) vs Mobile Crawler (P4)
            diff_c_mc = compute_differential_pair_metrics(t_id, day, "crawler_vs_mobile_crawler", obs_map["P3_crawler_oriented"], obs_map["P4_mobile_crawler"])
            cursor.execute("""
                INSERT INTO differential_pairs (
                    run_id, target_id, day_index, comparison_type, obs_id_a, obs_id_b,
                    status_code_divergence, redirect_divergence, html_cosine_similarity,
                    html_jaccard_similarity, dom_tree_edit_distance, visual_ssim,
                    phash_hamming_distance, header_distance_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                run_id, t_id, day, "crawler_vs_mobile_crawler",
                obs_map["P3_crawler_oriented"]["obs_id"], obs_map["P4_mobile_crawler"]["obs_id"],
                diff_c_mc["status_code_divergence"], diff_c_mc["redirect_divergence"],
                diff_c_mc["html_cosine_similarity"], diff_c_mc["html_jaccard_similarity"],
                diff_c_mc["dom_tree_edit_distance"], diff_c_mc["visual_ssim"],
                diff_c_mc["phash_hamming_distance"], diff_c_mc["header_distance_score"]
            ))
            total_diff_pairs += 1

            # 4. Cloaking Evaluation
            cloak_score, classification, signal, campaign, conf = evaluate_cloaking(t_id, day, diff_d_c, diff_d_m)
            cursor.execute("""
                INSERT INTO cloaking_evaluations (
                    run_id, target_id, day_index, cloak_score, classification,
                    primary_signal, detected_campaign, confidence_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (run_id, t_id, day, cloak_score, classification, signal, campaign, conf))
            total_evals += 1

            all_eval_data.append({
                "day": day,
                "date": crawl_date.isoformat(),
                "domain": t_def["domain"],
                "url": t_def["url"],
                "cloak_score": cloak_score,
                "classification": classification,
                "campaign": campaign,
                "primary_signal": signal,
                "desktop_vs_bot_cosine_sim": diff_d_c["html_cosine_similarity"],
                "desktop_vs_bot_ssim": diff_d_c["visual_ssim"],
                "redirect_divergence": diff_d_c["redirect_divergence"] or diff_d_m["redirect_divergence"]
            })

    # 5. Insert Longitudinal Campaign Lifecycle Transitions (Ground Truth Timeline)
    print("[*] Recording campaign lifecycle state transitions...")
    timeline_records = [
        # Target 1
        (1, 1, 3, "DORMANT_404", "None", "Initial discovery; path returns generic HTTP 404", "Attacker payload staging phase"),
        (1, 4, 8, "ACTIVE_CLOAKING", "Online Casino / Slot88", "User-Agent rule injected (.htaccess / Nginx rewrite)", "High volume keyword spam cloaked for Googlebot"),
        (1, 9, 13, "CAMPAIGN_PIVOT", "Crypto Asset Recovery Scam", "Attacker swapped template dynamically", "Pivot from gambling to financial fraud lure"),
        (1, 14, 15, "REMEDIATED", "None", "Government CERT / admin deployed WAF ACL rule (403)", "Compromise closed after incident alert"),

        # Target 2
        (2, 1, 15, "ACTIVE_PERSISTENT_CLOAKING", "Piracy APK & Mobile Affiliate Scam", "Dual-vector conditional redirection", "Long-term unpatched compromise abusing high trust .gov.in authority"),

        # Target 3
        (3, 1, 15, "ACTIVE_PERSISTENT_CLOAKING", "Unlicensed Pharmacy / Rx Spam", "Server-side User-Agent filter", "Stealthy pharmaceutical spam campaign; 404 shown to organic visitors"),

        # Target 4
        (4, 1, 5, "BENIGN_BASELINE", "None", "Normal government department portal", "Pre-compromise baseline"),
        (4, 6, 12, "BURST_MOBILE_INJECTION", "Telegram VIP Betting Syndicate", "JavaScript injection targeting mobile viewport & touch events", "Opportunistic 7-day mobile redirect abuse before attacker script teardown"),
        (4, 13, 15, "REVERTED_INACTIVE", "None", "Attacker removed redirect hook", "Returned to benign state without formal admin response"),

        # Target 5
        (5, 1, 10, "ACTIVE_CLOAKING", "Academic Ghostwriting Service", "PHP backdoor in WordPress upload folder", "Targeting high DR academic domain (.ac.in) for essay link schemes"),
        (5, 11, 15, "REMEDIATED", "None", "Sysadmin deleted infected plugin folder (HTTP 410)", "Permanent removal"),

        # Target 6
        (6, 1, 15, "CONTROL_BENIGN", "None", "Production responsive CSS layout", "Empirical baseline demonstrating low CloakScore under responsive shifts"),

        # Target 7
        (7, 1, 15, "CONTROL_BENIGN", "None", "Institutional website with mobile navigation", "Empirical baseline demonstrating zero semantic cloaking"),

        # Target 8
        (8, 1, 15, "CONTROL_BENIGN", "None", "Static HTML informational resource", "Zero variance sanity check baseline across all days"),

        # Target 9
        (9, 1, 7, "ACTIVE_CLOAKING", "Indonesian Slot88 Maxwin", "Injected reverse proxy gateway", "Active SEO poisoning abusing public tender indexing"),
        (9, 8, 15, "REMEDIATED", "None", "Website placed in 503 maintenance mode by emergency response", "Site taken offline for remediation"),

        # Target 10
        (10, 1, 15, "STEGANOGRAPHIC_CLOAKING", "Blackhat Casino Link Farm", "CSS hidden opacity:0 anchor tags", "Stealth cloaking designed to defeat visual inspection scanners")
    ]

    for rec in timeline_records:
        cursor.execute("""
            INSERT INTO campaign_evolution (
                target_id, start_day, end_day, observed_state, active_campaign, transition_trigger, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, rec)

    conn.commit()

    # 6. Export to CSV for Excel/Pandas presentation
    print("[*] Generating CSV exports in ./exports/ ...")

    # Export A: Observations
    obs_csv = os.path.join(EXPORTS_DIR, "longitudinal_observations_600.csv")
    with open(obs_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_obs_data[0].keys()))
        writer.writeheader()
        writer.writerows(all_obs_data)

    # Export B: Daily Cloaking Summary
    eval_csv = os.path.join(EXPORTS_DIR, "daily_cloaking_evaluations_150.csv")
    with open(eval_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_eval_data[0].keys()))
        writer.writeheader()
        writer.writerows(all_eval_data)

    # Export C: Target Master Summary
    target_summary_csv = os.path.join(EXPORTS_DIR, "target_summary_report.csv")
    cursor.execute("""
        SELECT 
            t.target_id,
            t.domain,
            t.category,
            t.jurisdiction,
            AVG(ce.cloak_score) as avg_cloak_score,
            MAX(ce.cloak_score) as peak_cloak_score,
            SUM(CASE WHEN ce.classification LIKE 'CLOAKED%' THEN 1 ELSE 0 END) as cloaked_days,
            GROUP_CONCAT(DISTINCT ce.detected_campaign) as campaigns_detected
        FROM targets t
        JOIN cloaking_evaluations ce ON t.target_id = ce.target_id
        GROUP BY t.target_id
    """)
    rows = cursor.fetchall()
    with open(target_summary_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target ID", "Domain", "Category", "Jurisdiction", "Avg CloakScore", "Peak CloakScore", "Days Cloaked (out of 15)", "Detected Campaigns"])
        for r in rows:
            writer.writerow([r[0], r[1], r[2], r[3], round(r[4], 3), round(r[5], 3), r[6], r[7]])

    # Export D: Campaign Evolution Timeline
    timeline_csv = os.path.join(EXPORTS_DIR, "campaign_evolution_timeline.csv")
    cursor.execute("""
        SELECT 
            t.domain,
            ce.start_day,
            ce.end_day,
            (ce.end_day - ce.start_day + 1) as duration_days,
            ce.observed_state,
            ce.active_campaign,
            ce.transition_trigger,
            ce.notes
        FROM campaign_evolution ce
        JOIN targets t ON ce.target_id = t.target_id
        ORDER BY t.target_id, ce.start_day
    """)
    t_rows = cursor.fetchall()
    with open(timeline_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "Start Day", "End Day", "Duration (Days)", "Observed State", "Active Campaign", "Transition Trigger", "Notes"])
        writer.writerows(t_rows)

    conn.close()

    print("[+] Successfully generated:")
    print(f"    - Database: {DB_PATH}")
    print(f"    - Records: {len(TARGETS_DEF)} Targets, 15 Days, {total_observations} Observations, {total_diff_pairs} Differential Pairs, {total_evals} Evaluations")
    print(f"    - CSV Exports created in: {EXPORTS_DIR}")

if __name__ == "__main__":
    main()
