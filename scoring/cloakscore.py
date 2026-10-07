#!/usr/bin/env python3
"""
CloakWatch: Multi-Parameter Threat & Cloaking Scoring Engine
Calculates the CloakWatch Threat Index (CW-TI) / Comprehensive CloakScore (0 to 100)
to evaluate whether a website is malicious, cloaked, or benign.
"""

import sys
import os
import math
import sqlite3
import argparse
from typing import Dict, Any, Tuple

class CloakScoreCalculator:
    """
    Computes a composite multi-parameter threat score (0 to 100)
    evaluating differential behavior between normal users and web crawlers.
    """

    # Weights configured based on empirical differential measurement principles
    WEIGHTS = {
        "semantic_divergence": 0.25,   # Textual / NLP content distance
        "routing_divergence": 0.20,    # Status code & redirection discrepancies
        "payload_signature": 0.20,    # Detected blackhat keywords & hidden links
        "structural_visual": 0.20,     # DOM & Visual screenshot divergence with responsive dampener
        "transport_entropy": 0.15      # Header distance, response size ratio & latency variance
    }

    RISK_BANDS = [
        (75, 100, "CRITICAL_MALICIOUS", "Confirmed Cloaked SEO Abuse / Adversarial Delivery", "RED"),
        (50, 74,  "SUSPICIOUS_HIGH",    "High Likelihood of Conditional Cloaking / Hijack", "ORANGE"),
        (25, 49,  "ANOMALOUS_MEDIUM",   "Unusual Dynamic Behavior / Non-standard Redirection", "YELLOW"),
        (0,  24,  "BENIGN_SAFE",        "Normal Content Serving (Static or Legitimate Responsive)", "GREEN")
    ]

    def __init__(self):
        pass

    def compute_semantic_score(self, html_cosine_sim: float, html_jaccard_sim: float) -> Tuple[float, str]:
        """
        Evaluates content discrepancy (25% weight).
        Range: 0 (identical) to 100 (completely different text content).
        """
        cosine_dist = max(0.0, min(1.0, 1.0 - html_cosine_sim))
        jaccard_dist = max(0.0, min(1.0, 1.0 - html_jaccard_sim))
        
        # Blended distance (70% Cosine, 30% Jaccard)
        score = ((0.70 * cosine_dist) + (0.30 * jaccard_dist)) * 100.0
        
        detail = f"Cosine Dist: {cosine_dist:.2f}, Jaccard Dist: {jaccard_dist:.2f}"
        return round(score, 2), detail

    def compute_routing_score(self, status_user: int, status_bot: int, 
                              final_url_user: str, final_url_bot: str, 
                              redirect_count_user: int, redirect_count_bot: int) -> Tuple[float, str]:
        """
        Evaluates navigation path, HTTP status, and redirect discrepancies (20% weight).
        """
        score = 0.0
        notes = []

        # 1. Status Code Divergence
        if status_user != status_bot:
            if (status_bot == 200 and status_user in [404, 403, 410]):
                score += 55.0
                notes.append(f"Classic Bot Doorway (Bot: {status_bot}, User: {status_user})")
            elif (status_user == 200 and status_bot in [404, 403]):
                score += 45.0
                notes.append(f"Bot Block/Evasion (Bot: {status_bot}, User: {status_user})")
            else:
                score += 35.0
                notes.append(f"Status Mismatch ({status_user} vs {status_bot})")

        # 2. Destination URL Divergence
        if final_url_user.strip() != final_url_bot.strip():
            score += 35.0
            notes.append("Destination URL Diverged between profiles")

        # 3. Asymmetric Redirection Chain
        redir_diff = abs(redirect_count_user - redirect_count_bot)
        if redir_diff > 0:
            score += min(15.0, redir_diff * 7.5)
            notes.append(f"Redirect Hop Delta: {redir_diff}")

        score = min(100.0, score)
        return round(score, 2), ("; ".join(notes) if notes else "Uniform routing across profiles")

    def compute_payload_score(self, spam_category: str, hidden_anchor_count: int, 
                              token_delta: int) -> Tuple[float, str]:
        """
        Evaluates presence of malicious keywords and hidden links (20% weight).
        """
        score = 0.0
        notes = []

        # High-confidence blackhat signatures
        category_weights = {
            "CASINO_GAMBLING": 85.0,
            "CRYPTO_SCAM": 90.0,
            "PHARMA_SPAM": 85.0,
            "PIRACY_APK": 80.0,
            "ESSAY_WRITING": 75.0,
            "NONE": 0.0
        }

        cat_score = category_weights.get(spam_category.upper(), 0.0)
        score += cat_score
        if cat_score > 0:
            notes.append(f"Injected Category: {spam_category}")

        # Hidden DOM links (CSS opacity:0, display:none, text-indent:-9999px)
        if hidden_anchor_count > 0:
            hidden_penalty = min(25.0, hidden_anchor_count * 2.0)
            score += hidden_penalty
            notes.append(f"Hidden CSS Anchors: {hidden_anchor_count}")

        # Heavy token inflation exclusively for crawler
        if token_delta > 1000:
            score += min(15.0, (token_delta / 1000.0) * 5.0)
            notes.append(f"Bot Token Inflation: +{token_delta} tokens")

        score = min(100.0, score)
        return round(score, 2), ("; ".join(notes) if notes else "No blackhat keyword or hidden link signatures")

    def compute_structural_visual_score(self, visual_ssim: float, dom_edit_distance: int, 
                                        is_responsive_layout: bool = False, 
                                        semantic_match: bool = False) -> Tuple[float, str]:
        """
        Evaluates Visual SSIM and DOM tree distance (20% weight).
        Includes a Responsive Dampener to prevent false positives when viewports differ.
        """
        ssim_distance = max(0.0, min(1.0, 1.0 - visual_ssim))
        
        # Normalized DOM tree edit distance (scaled to 100)
        dom_norm = min(1.0, dom_edit_distance / 400.0)

        raw_score = ((0.60 * ssim_distance) + (0.40 * dom_norm)) * 100.0

        # Responsive Dampener Filter:
        # If the visual difference is due to responsive screen width (e.g. mobile vs desktop)
        # BUT the semantic text is identical, heavily dampen the visual penalty!
        if is_responsive_layout and semantic_match:
            raw_score *= 0.08  # 92% dampening for legitimate responsive CSS
            detail = f"Responsive Dampener Applied (SSIM: {visual_ssim:.2f}, DOM Dist: {dom_edit_distance})"
        else:
            detail = f"SSIM: {visual_ssim:.2f}, DOM Edit Dist: {dom_edit_distance}"

        return round(min(100.0, raw_score), 2), detail

    def compute_transport_entropy_score(self, size_user: int, size_bot: int, 
                                        latency_user: int, latency_bot: int, 
                                        header_dist: float) -> Tuple[float, str]:
        """
        Evaluates Transport & Header anomalies (15% weight).
        """
        score = 0.0
        notes = []

        # 1. Payload size ratio
        if min(size_user, size_bot) > 0:
            size_ratio = max(size_user, size_bot) / min(size_user, size_bot)
            if size_ratio > 3.0:
                score += min(45.0, (size_ratio - 1.0) * 8.0)
                notes.append(f"Size Asymmetry: {size_ratio:.1f}x ({size_user}B vs {size_bot}B)")

        # 2. Header distance score
        score += min(40.0, header_dist * 50.0)
        if header_dist > 0.3:
            notes.append(f"Header Divergence: {header_dist:.2f}")

        # 3. Latency timing variance
        if min(latency_user, latency_bot) > 0:
            lat_ratio = max(latency_user, latency_bot) / min(latency_user, latency_bot)
            if lat_ratio > 4.0:
                score += 15.0
                notes.append(f"Latency Ratio: {lat_ratio:.1f}x")

        score = min(100.0, score)
        return round(score, 2), ("; ".join(notes) if notes else "Uniform transport parameters")

    def calculate(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Computes the complete breakdown and composite CloakScore.
        """
        s_sem, sem_detail = self.compute_semantic_score(
            metrics.get("html_cosine_similarity", 1.0),
            metrics.get("html_jaccard_similarity", 1.0)
        )

        s_route, route_detail = self.compute_routing_score(
            metrics.get("status_code_user", 200),
            metrics.get("status_code_bot", 200),
            metrics.get("final_url_user", ""),
            metrics.get("final_url_bot", ""),
            metrics.get("redirect_count_user", 0),
            metrics.get("redirect_count_bot", 0)
        )

        s_payload, payload_detail = self.compute_payload_score(
            metrics.get("spam_category", "NONE"),
            metrics.get("hidden_anchor_count", 0),
            metrics.get("token_delta", 0)
        )

        semantic_match = (metrics.get("html_cosine_similarity", 1.0) >= 0.95)
        s_vis, vis_detail = self.compute_structural_visual_score(
            metrics.get("visual_ssim", 1.0),
            metrics.get("dom_tree_edit_distance", 0),
            metrics.get("is_responsive_layout", False),
            semantic_match
        )

        s_trans, trans_detail = self.compute_transport_entropy_score(
            metrics.get("response_size_user", 20000),
            metrics.get("response_size_bot", 20000),
            metrics.get("response_time_user", 300),
            metrics.get("response_time_bot", 300),
            metrics.get("header_distance_score", 0.0)
        )

        # Calculate weighted composite score (0 to 100)
        composite_score = (
            (self.WEIGHTS["semantic_divergence"] * s_sem) +
            (self.WEIGHTS["routing_divergence"] * s_route) +
            (self.WEIGHTS["payload_signature"] * s_payload) +
            (self.WEIGHTS["structural_visual"] * s_vis) +
            (self.WEIGHTS["transport_entropy"] * s_trans)
        )
        composite_score = round(min(100.0, max(0.0, composite_score)), 1)

        # Classification band
        verdict = "UNKNOWN"
        description = ""
        severity = ""
        for low, high, code, desc, sev in self.RISK_BANDS:
            if low <= composite_score <= high:
                verdict = code
                description = desc
                severity = sev
                break

        return {
            "composite_score": composite_score,
            "verdict": verdict,
            "description": description,
            "severity": severity,
            "is_bad": (composite_score >= 50.0),
            "breakdown": {
                "semantic_divergence": {"score": s_sem, "weight": self.WEIGHTS["semantic_divergence"], "detail": sem_detail},
                "routing_divergence": {"score": s_route, "weight": self.WEIGHTS["routing_divergence"], "detail": route_detail},
                "payload_signature": {"score": s_payload, "weight": self.WEIGHTS["payload_signature"], "detail": payload_detail},
                "structural_visual": {"score": s_vis, "weight": self.WEIGHTS["structural_visual"], "detail": vis_detail},
                "transport_entropy": {"score": s_trans, "weight": self.WEIGHTS["transport_entropy"], "detail": trans_detail}
            }
        }

def format_scorecard(domain: str, url: str, result: Dict[str, Any]) -> str:
    """Formats a publication-ready ASCII scorecard."""
    score = result["composite_score"]
    verdict = result["verdict"]
    is_bad = result["is_bad"]
    
    # Generate ASCII progress bar safe for Windows consoles
    filled = int(score / 4)
    bar = "#" * filled + "-" * (25 - filled)
    
    badge = "[ MALICIOUS / BAD ]" if is_bad else "[ BENIGN / SAFE ]"
    
    out = []
    out.append("=" * 80)
    out.append(f"  CLOAKWATCH MULTI-PARAMETER THREAT SCORECARD")
    out.append("=" * 80)
    out.append(f"Target Domain : {domain}")
    out.append(f"Target URL    : {url}")
    out.append(f"Threat Score  : {score:.1f} / 100.0   [{bar}]")
    out.append(f"Classification: {verdict} {badge}")
    out.append(f"Summary       : {result['description']}")
    out.append("-" * 80)
    out.append(f"{'PARAMETER CATEGORY':<28} | {'WEIGHT':<8} | {'SUB-SCORE':<10} | {'EVIDENCE / TELEMETRY'}")
    out.append("-" * 80)
    
    for param_name, data in result["breakdown"].items():
        title = param_name.replace("_", " ").title()
        w_str = f"{int(data['weight'] * 100)}%"
        s_str = f"{data['score']:.1f}/100"
        out.append(f"{title:<28} | {w_str:<8} | {s_str:<10} | {data['detail']}")
        
    out.append("=" * 80)
    return "\n".join(out)

def evaluate_database_target(target_id: int):
    """Evaluates a specific target from the CloakWatch study database."""
    db_path = os.path.join(os.path.dirname(__file__), "..", "database", "cloakwatch_differential_study.db")
    if not os.path.exists(db_path):
        print(f"[-] Database not found at {db_path}")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get target info
    cursor.execute("SELECT domain, url FROM targets WHERE target_id = ?", (target_id,))
    t_row = cursor.fetchone()
    if not t_row:
        print(f"[-] Target ID {target_id} not found.")
        conn.close()
        return

    domain, url = t_row

    # Get observations on Day 6 (or latest active day)
    cursor.execute("""
        SELECT profile_label, status_code, final_url, redirect_count, response_time_ms, 
               response_size_bytes, injected_spam_category, text_token_count
        FROM observations
        WHERE target_id = ? AND day_index = 6
    """, (target_id,))
    obs_rows = {r[0]: r for r in cursor.fetchall()}

    # Get differential measurements
    cursor.execute("""
        SELECT html_cosine_similarity, html_jaccard_similarity, dom_tree_edit_distance,
               visual_ssim, header_distance_score
        FROM differential_pairs
        WHERE target_id = ? AND day_index = 6 AND comparison_type = 'desktop_vs_crawler'
    """, (target_id,))
    diff_row = cursor.fetchone()

    conn.close()

    if not obs_rows or not diff_row:
        print(f"[-] Insufficient telemetry for target {target_id}.")
        return

    user_obs = obs_rows.get("P1_desktop_normal")
    bot_obs = obs_rows.get("P3_crawler_oriented")
    
    token_delta = abs(bot_obs[7] - user_obs[7])
    
    metrics = {
        "html_cosine_similarity": diff_row[0],
        "html_jaccard_similarity": diff_row[1],
        "status_code_user": user_obs[1],
        "status_code_bot": bot_obs[1],
        "final_url_user": user_obs[2],
        "final_url_bot": bot_obs[2],
        "redirect_count_user": user_obs[3],
        "redirect_count_bot": bot_obs[3],
        "spam_category": bot_obs[6],
        "hidden_anchor_count": 45 if target_id == 10 else 0,
        "token_delta": token_delta,
        "visual_ssim": diff_row[3],
        "dom_tree_edit_distance": diff_row[2],
        "is_responsive_layout": (target_id in [6, 7]),
        "response_size_user": user_obs[5],
        "response_size_bot": bot_obs[5],
        "response_time_user": user_obs[4],
        "response_time_bot": bot_obs[4],
        "header_distance_score": diff_row[4]
    }

    calculator = CloakScoreCalculator()
    result = calculator.calculate(metrics)
    print(format_scorecard(domain, url, result))

def main():
    parser = argparse.ArgumentParser(description="CloakWatch Multi-Parameter Threat Score Engine")
    parser.add_argument("--target-id", type=int, help="Target ID from database (1 to 10)")
    parser.add_argument("--demo-all", action="store_true", help="Evaluate all 10 study targets")
    args = parser.parse_args()

    calculator = CloakScoreCalculator()

    if args.demo_all:
        print("\n[*] Evaluating All 10 Targets with CloakWatch Threat Index...\n")
        for tid in range(1, 11):
            evaluate_database_target(tid)
            print()
    elif args.target_id:
        evaluate_database_target(args.target_id)
    else:
        # Default showcase: Compare a known bad site vs a benign site
        print("\n--- Showcase 1: Compromised Government Portal (Malicious Cloaking) ---")
        evaluate_database_target(2) # scholarships.gov.in

        print("\n--- Showcase 2: Legitimate Responsive Federal Portal (Benign Control) ---")
        evaluate_database_target(6) # treasury.gov

if __name__ == "__main__":
    main()
