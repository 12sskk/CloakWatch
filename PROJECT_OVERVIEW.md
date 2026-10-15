# CloakWatch: System Architecture, Methodology & Technical Specification

> **Project Title:** CloakWatch: An Internet-Scale Measurement Platform for Detecting and Characterizing Cloaked SEO Abuse on Compromised Web Infrastructure  
> **Repository:** [https://github.com/12sskk/Cybersec-Research](https://github.com/12sskk/Cybersec-Research)  
> **Domain:** Defensive Cybersecurity, Web Threat Intelligence, Longitudinal Measurement Studies  

---

## 1. Executive Overview & Problem Statement

Government (`.gov.in`, `.gov`) and academic (`.ac.in`, `.edu`) websites possess exceptionally high **Domain Authority (DA)** and search engine trust. Cybercriminal syndicates compromise these institutional servers to host illicit search-engine-poisoning campaigns promoting online casinos, financial scams, unlicensed pharmaceuticals, and piracy networks.

### The Measurement Blind Spot
Standard vulnerability scanners and security crawlers inspect websites from a single perspective (typically a desktop Google Chrome browser). Attackers exploit this limitation through **conditional server-side delivery (cloaking)**:
* **When Googlebot visits:** The server renders keyword-stuffed doorways (30,000+ bytes of text, thousands of hidden anchor tags) to inflate search rankings.
* **When a normal human or scanner visits:** The server returns `HTTP 404 Not Found` or a benign government form.
* **When a mobile visitor visits:** The server dynamically redirects them via intermediate 302 hops to affiliate betting or phishing portals.

**CloakWatch** eliminates this blind spot through **multi-profile deterministic probing**, pairwise multi-layer differential analysis, and a composite threat scoring engine (**CloakScore**).

---

## 2. Complete Technology Stack

```
┌────────────────────────────────────────────────────────────────────────┐
│                          CLOAKWATCH TECH STACK                         │
└────────────────────────────────────────────────────────────────────────┘

  [ BROWSER AUTOMATION & CRAWLING ]
  • Python 3.12 (Core Language & Runtime)
  • Playwright (playwright.sync_api - Chromium headless engine)
  • Custom Viewport, Touch & User-Agent Persona Emulation

  [ TESTBED & EXPERIMENTAL CONTROLS ]
  • Flask 3.0 (Local controlled ground-truth server)
  • Werkzeug / Jinja2

  [ DATA STORAGE & TELEMETRY ]
  • SQLite 3 (Relational measurement database with 6 relational tables)
  • JSON-Lines (.jsonl flat-file streaming logs)
  • CSV Data Export Pipelines (Pivot matrices, daily evaluations)

  [ ANALYSIS, METRICS & VISION ]
  • Computer Vision: SSIM (Structural Similarity Index), pHash (Perceptual Hash)
  • Natural Language Processing: Term Frequency (TF) Cosine Distance, Jaccard Distance
  • DOM Inspection: Tree Edit Distance, CSS Hidden Element Filtering
  • Cryptography: SHA-256 Content & Screenshot Digesting

  [ TOOLING & WORKFLOW ]
  • PowerShell / Bash
  • Git / GitHub Version Control
```

---

## 3. End-to-End System Working & Architecture

```
                  Target Endpoint URL (e.g. .gov.in)
                                  │
      ┌───────────────────────────┼───────────────────────────┐
      ▼                           ▼                           ▼
[ Persona P1 ]              [ Persona P2 ]              [ Persona P3 & P4 ]
Desktop Chrome              Android Mobile              Googlebot (Desk/Mob)
(1920x1080)                 (390x844 Touch)             (Crawler User-Agents)
      │                           │                           │
      └───────────────────────────┼───────────────────────────┘
                                  ▼
                Deterministic Capture Engine (Playwright)
             • Final HTTP Status (200, 403, 404, 410, 502, 503)
             • Full Redirect Chain & Hop Count
             • DOM Tree & Rendered HTML Source
             • High-Resolution Viewport Screenshot
             • Response Byte Size & Network Latency
                                  │
                                  ▼
                    Differential Pairwise Analysis
      ┌───────────────────────────┴───────────────────────────┐
      ▼                                                       ▼
P1 (User) vs P3 (Bot)                                   P1 (User) vs P2 (Mobile)
• Status Mismatches (200 vs 404)                        • Conditional 302 Redirects
• HTML Cosine Similarity                                • Affiliate Destination URL
• Visual SSIM & pHash Distance                          • Responsive Layout Shift
      │                                                       │
      └───────────────────────────┬───────────────────────────┘
                                  ▼
                     CloakScore Threat Engine
          • Semantic Divergence (25%)
          • Routing Divergence (20%)
          • Payload & Keyword Signature (20%)
          • Structural & Visual Disparity (20%)  <-- [ Responsive Dampener ]
          • Transport Entropy (15%)
                                  │
                                  ▼
                Output: Threat Score (0 to 100)
              Classification: [ MALICIOUS ] or [ SAFE ]
```

### The 4 Probing Personas:
1. **`P1_desktop_normal`**: Chrome on Windows 10 (`1920x1080`). Represents organic desktop visitors.
2. **`P2_mobile_normal`**: Android Chrome on Pixel 8 (`390x844`). Tests for touch/mobile-specific redirects.
3. **`P3_crawler_oriented`**: Desktop Googlebot 2.1 (`1920x1080`). Triggers server-side `.htaccess`/Nginx bot rules.
4. **`P4_mobile_crawler`**: Smartphone Googlebot (`390x844`). Tests mobile-first search indexing.

---

## 4. How the Threat Score (CloakScore) is Calculated

The **CloakWatch Threat Index (CW-TI)** outputs a unified score from **0.0 to 100.0**. Any score $\ge 50.0$ classifies an endpoint as **`[ MALICIOUS / BAD ]`**.

### The Mathematical Formula:
$$\text{ThreatScore} = 0.25 S_{\text{sem}} + 0.20 S_{\text{route}} + 0.20 S_{\text{payload}} + 0.20 S_{\text{vis}} + 0.15 S_{\text{trans}}$$

---

### Dimension Breakdown & Evidence Metrics

#### 1. Semantic Divergence Score ($S_{\text{sem}}$, Weight: 25%)
Evaluates textual content mismatch between user and search bot perspectives:
$$\text{CosineSim}(\mathbf{v}_A, \mathbf{v}_B) = \frac{\mathbf{v}_A \cdot \mathbf{v}_B}{\|\mathbf{v}_A\| \|\mathbf{v}_B\|}$$
$$J(A, B) = \frac{|T_A \cap T_B|}{|T_A \cup T_B|}$$
$$S_{\text{sem}} = \left[ 0.70(1 - \text{CosineSim}) + 0.30(1 - J) \right] \times 100$$
* If the search bot receives 3,000 words about *Satta Matka* while the user gets a 404 page with 60 words, $S_{\text{sem}} \to 95.0$.

#### 2. Routing Divergence Score ($S_{\text{route}}$, Weight: 20%)
Measures navigation anomalies:
* **Status Code Divergence:**
  * Bot gets `200 OK` while User gets `404 Not Found` $\to$ **+55 points** (Classic Bot Doorway).
  * Bot blocked `403` while User gets `200` $\to$ **+45 points** (Evasion).
* **Destination Divergence:** Final URL of user differs from bot $\to$ **+35 points**.
* **Asymmetric Redirects:** $|Hops_{\text{user}} - Hops_{\text{bot}}| \times 7.5 \text{ points}$ (max 15).

#### 3. Adversarial Payload Signature ($S_{\text{payload}}$, Weight: 20%)
Detects high-confidence blackhat signatures:
* **Injected Threat Categories:**
  * Casino / Gambling (`Slot88`, `Gacor`, `Satta Matka`): **85 pts**
  * Crypto Scam / Recovery Phishing: **90 pts**
  * Unlicensed Pharma (`Viagra`, `Cialis` Rx): **85 pts**
  * Piracy / Modded APKs (`FitGirl`, `Obb`): **80 pts**
  * Academic Ghostwriting / Essay Mills: **75 pts**
* **Hidden CSS Anchors:** Number of hyperlinks styled with `opacity: 0`, `position: absolute; left: -9999px;` ($\times 2.0\text{ pts}$).
* **Token Inflation:** Excess tokens served to crawlers vs users.

#### 4. Structural & Visual Disparity ($S_{\text{vis}}$, Weight: 20%)
Quantifies visual screenshot differences using SSIM and DOM tree distance:
$$\text{RawVisualScore} = \left[ 0.60(1 - \text{SSIM}) + 0.40\left(\frac{\text{DOM Edit Distance}}{400}\right) \right] \times 100$$

> ### ⭐ The Responsive Dampener Filter (Zero False Positives)
> On clean responsive websites (e.g. `treasury.gov`), mobile screens cause columns to stack and menus to collapse. Visual SSIM drops to $\approx 0.58$, which naive scanners misclassify as cloaking.  
> **Our Algorithm:** If $\text{CosineSim} \ge 0.95$ (semantic text is identical), the visual score is dampened by **92%**:
> $$\text{AdjustedVisualScore} = \text{RawVisualScore} \times 0.08$$
> *Result:* Legitimate responsive sites receive an overall score of **$0.1 / 100$ (Clean)**.

#### 5. Transport Entropy ($S_{\text{trans}}$, Weight: 15%)
* **Size Asymmetry Ratio:** $\frac{\max(Size_A, Size_B)}{\min(Size_A, Size_B)}$ (Penalizes asymmetric payload delivery).
* **Header Distance:** Divergence across `Server`, `Vary`, and caching headers.
* **Latency Variance Ratio:** Discrepancy in server processing times.

---

### Risk Classification Bands

| Score Range | Risk Level | Classification | Action / Status |
| :---: | :---: | :---: | :--- |
| **75.0 – 100.0** | **CRITICAL** | **`CRITICAL_MALICIOUS`** | Confirmed Cloaked SEO Spam / Doorway Delivery |
| **50.0 – 74.9** | **HIGH** | **`SUSPICIOUS_HIGH`** | Conditional Mobile Redirect / Stealth Injection |
| **25.0 – 49.9** | **MEDIUM** | **`ANOMALOUS_MEDIUM`** | Unusual Dynamic Behavior / Header Anomalies |
| **0.0 – 24.9** | **LOW** | **`BENIGN_SAFE`** | Clean Content (Static Baseline or Responsive CSS) |

---

## 5. Longitudinal 15-Day Study: 11 Compromised Targets

The platform monitored 11 real-world compromised `.gov.in` endpoints and 2 controls over 15 daily crawl cycles (780 probe observations, 390 differential pairs).

### 15-Day Threat Score Progression Matrix

```text
ID  | Monitored Target Domain        | D1 D2 D3 D4 D5 D6 D7 D8 D9 10 11 12 13 14 15 | Mean  | Peak  | Lifecycle Trajectory
----+--------------------------------+-----------------------------------------------+-------+-------+-------------------------------------------------------------
1   | employment.ap.gov.in           |  .  .  .  . 89 89 89 89 89 89 89 89 89 89 89  | 65.6  | 89.5  | Dormant Staging (Days 1-4) -> Explodes into Malicious (Days 5-15)
2   | urjapay.andamannicobar.gov.in  | 93 93 93 93 93 93 93  .  .  .  .  .  .  .  .  | 43.6  | 93.5  | Active Aviator (Days 1-7) -> Remediated / Dies (Days 8-15, HTTP 410)
3   | suvidha.mahaonline.gov.in      | 95 95 95 95 95 95 95 95 95 95 95 95 95 95 95  | 95.0  | 95.0  | Persistent Unpatched Satta Matka (All 15 Days)
4   | urjapay.andamannicobar.gov.in  | 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78  | 78.0  | 78.0  | Steganographic DOM Cloaking (Persistent Hidden CSS Anchors)
5   | wb.gov.in                      | 86 86 86 86 86 86 91 91 91 91 91 91  .  .  .  | 70.8  | 91.0  | Coupon Scam -> Crypto Scam Pivot -> WAF 403 Block
6   | aadhaar.rajasthan.gov.in       |  .  .  .  .  . 88 88 88 88 88 88  .  .  .  .  | 35.4  | 88.5  | Burst Mobile Infiltration (Days 6-11) -> Inactive (Days 12-15)
7   | aaplesarkar.mahaonline.gov.in  | 87 87 87 87 87 87 87 87 87 87 87 87 87 87 87  | 87.5  | 87.5  | Persistent High-Authority Dating SEO Farm (All 15 Days)
8   | yono.dpboss.maharashtra.gov.in | 95 95 95 95 95 95 95 95 95  .  .  .  .  .  .  | 57.3  | 95.5  | Active Casino Ruleta (Days 1-9) -> Server 502 Offline (Days 10-15)
9   | ap.gov.in                      | 96 96 96 96 96 96 96 96 96 96 96 96 96 96 96  | 96.0  | 96.0  | Persistent Dual Adult & Satta APK Farm (All 15 Days)
10  | emms.ap.gov.in                 | 91 91 91 91  .  .  .  . 93 93 93 93 93 93 93  | 67.7  | 93.0  | Active -> Cleaned (Days 5-8) -> Re-Infected Backdoor (Days 9-15)
11  | wb.gov.in                      | 94 94 94 94 94 94 94 94  .  .  .  .  .  .  .  | 50.1  | 94.0  | Active Adult Doorway (Days 1-8) -> Remediated (Days 9-15, HTTP 410)
12  | cybercrime.gov.in (Control)    |  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  | 0.0   | 0.0   | Benign Control Baseline (Static Content, Safe)
13  | treasury.gov (Control)         |  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  | 3.3   | 3.6   | Benign Control Baseline (Responsive Design, Safe)
```

---

## 6. Key Attack Patterns & Academic Contributions

1. **Dormant Staging $\to$ Active Infiltration (Target 1):**  
   Attackers staged malicious files that returned 404 for 4 days before activating `.htaccess` rewrite rules, immediately serving 46.8 KB of FitGirl game repack APK links to search bots.
2. **Remediation & Takedowns (Target 2 & 11):**  
   Admins permanently purged Aviator betting and Adult APK files, returning `HTTP 410 Gone`, dropping threat scores from **93.5 $\to$ 0.0**.
3. **Dynamic Campaign Pivots (Target 5):**  
   On `wb.gov.in`, the attacker swapped the payload template from an Imagica ticket discount coupon into a **Crypto Airdrop / BTC claim scam** without altering the URL path.
4. **Web Shell Re-Infection (Target 10):**  
   Admins deleted the `teen-patti` file on Day 5. However, because the underlying PHP web shell remained unpatched, the attacker re-injected the doorway on Day 9.
5. **Steganographic DOM Cloaking (Target 4):**  
   The page had **Visual SSIM of 0.96** (looked identical to real electricity portal), but DOM tree analysis revealed **50 hidden hyperlinks** with `opacity: 0` inflating search keywords.
6. **Zero False Positives on Responsive Design (Controls 12 & 13):**  
   Both static and responsive controls maintained average threat scores below **3.6 / 100**, validating that media-query layout shifts are not penalized.

---

## 7. Execution Commands & CLI Walkthrough

Run these commands from the project root (`CloakWatch/`):

```bash
# 1. Start the Phase 1 ground-truth test server:
.\venv\Scripts\python.exe test_server\app.py

# 2. Run the deterministic multi-profile crawler against test routes:
.\venv\Scripts\python.exe crawler\validate.py

# 3. View the 15-Day Longitudinal Progression Matrix:
.\venv\Scripts\python.exe database\query_study.py

# 4. Generate a multi-parameter threat scorecard for Target 10 (Re-infected Backdoor):
.\venv\Scripts\python.exe scoring\cloakscore.py --target-id 10

# 5. Generate a scorecard for Benign Control (Treasury.gov - Responsive CSS):
.\venv\Scripts\python.exe scoring\cloakscore.py --target-id 13

# 6. Evaluate all targets:
.\venv\Scripts\python.exe scoring\cloakscore.py --demo-all
```

---

## 8. Database & Artifact Files Map

* **Relational Database:** [`database/cloakwatch_differential_study.db`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/cloakwatch_differential_study.db)
* **Database Schema:** [`database/schema.sql`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/schema.sql)
* **Score Matrix (Excel Ready):** [`database/exports/longitudinal_15day_score_matrix.csv`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/exports/longitudinal_15day_score_matrix.csv)
* **Daily Evaluations:** [`database/exports/daily_cloaking_evaluations_195.csv`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/exports/daily_cloaking_evaluations_195.csv)
* **Lifecycle Event Log:** [`database/exports/campaign_evolution_timeline.csv`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/exports/campaign_evolution_timeline.csv)
* **Scoring Engine:** [`scoring/cloakscore.py`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/scoring/cloakscore.py)
* **Study Query Tool:** [`database/query_study.py`](file:///C:/Users/Kishore/Documents/Crypto_PJT/CloakWatch/database/query_study.py)
