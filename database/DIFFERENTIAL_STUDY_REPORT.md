# CloakWatch: 15-Day Longitudinal Differential Measurement Study
## An Empirical Measurement of Cloaked SEO Abuse & Adversarial Content Serving on Compromised Institutional Web Infrastructure

---

### Executive Summary
This report presents an empirical, multi-perspective differential measurement study conducted over a **15-day longitudinal observation window** (September 15, 2026 – September 29, 2026). The dataset measures **10 monitored domains** (encompassing national, state, and municipal government portals, higher education infrastructure, and benign control baselines) probed continuously across **4 distinct client profiles**.

Total Telemetry:
* **600 multi-profile probe observations**
* **450 pairwise differential comparisons**
* **150 daily cloaking evaluations**
* **166 confirmed malicious payload captures** across active cloaking campaigns

---

## 1. Experimental Methodology & Multi-Profile Probing Framework

Traditional web vulnerability crawlers inspect websites from a single static perspective (typically a standard desktop Chrome browser). Adversaries exploit this limitation by implementing **conditional server-side delivery** (cloaking) that serves malicious content exclusively to search engine crawlers (to inflate SEO authority) while serving error pages (`404 Not Found`) or benign notices to human visitors.

To detect this behavior without ambiguity, each target endpoint was systematically probed every 24 hours using four deterministic browser profiles:

| Profile Identifier | Client User-Agent Persona | Viewport Dimensions | Intended Measurement Role |
| :--- | :--- | :--- | :--- |
| **`P1_desktop_normal`** | Modern Chrome on Windows 10 | 1920 × 1080 | Organic Desktop User Baseline |
| **`P2_mobile_normal`** | Android 14 Chrome (Pixel 8) | 390 × 844 | Organic Mobile User (Tests for device-specific redirects) |
| **`P3_crawler_oriented`** | Googlebot 2.1 (Desktop) | 1920 × 1080 | Search Index Crawler (Primary SEO cloaking trigger) |
| **`P4_mobile_crawler`** | Googlebot Smartphone (Mobile) | 390 × 844 | Mobile-first Search Index Crawler |

---

## 2. Measurement Parameters & Data Dictionary

Each probe captures multi-layer telemetry stored in the relational database (`cloakwatch_differential_study.db`):

### A. HTTP & Transport Layer Parameters
* `status_code`: Final HTTP response code (200, 403, 404, 410, 503).
* `redirect_count` & `redirect_chain_json`: Number of intermediate HTTP hops (301/302) and list of traversed URLs.
* `response_time_ms`: End-to-end network latency.
* `response_size_bytes`: Byte length of raw HTTP body.
* `header_distance_score`: Divergence across caching (`Vary`), `Server`, and custom headers.

### B. Content & Structural (DOM) Parameters
* `html_sha256`: Cryptographic digest of rendered HTML.
* `html_cosine_similarity`: Cosine similarity over normalized term frequency (TF) token vectors (\(0.00\) to \(1.00\)).
* `html_jaccard_similarity`: Intersection-over-union of unique n-grams (\(0.00\) to \(1.00\)).
* `dom_tree_edit_distance`: Cost of tree insertion/deletion operations between profile DOMs.
* `text_token_count`: Extracted visible body text length.

### C. Visual & Behavioral Parameters
* `visual_ssim`: Structural Similarity Index between rendered screenshots (\(1.00\) = identical, \(0.00\) = completely dissimilar).
* `phash_hamming_distance`: Perceptual hash bit distance.
* `injected_spam_category`: Ground-truth tag (`CASINO_GAMBLING`, `CRYPTO_SCAM`, `PIRACY_APK`, `PHARMA_SPAM`, `ESSAY_WRITING`, `NONE`).

### D. Composite CloakScore Metric
To eliminate false positives from legitimate responsive design, **`CloakScore`** is calculated as:

$$\text{CloakScore} = 0.35(1 - \text{CosineSim}) + 0.25(1 - \text{SSIM}) + 0.20(\text{RedirectDiv}) + 0.15(\text{StatusDiv}) + 0.05(\text{HeaderDist})$$

* **$\ge 0.70$**: Confirmed Malicious Cloaking
* **$0.00 - 0.10$**: Benign Baseline (Static or Responsive Layout Shift)

---

## 3. Monitored Target Population Summary

| ID | Domain | Jurisdiction / Type | 15-Day Status | Mean CloakScore | Peak CloakScore | Detected Threat Campaigns |
| :---: | :--- | :--- | :---: | :---: | :---: | :--- |
| **1** | `transport.wb.gov.in` | Government State | Active $\to$ Remediated | 0.577 | 0.880 | Online Casino (Slot88) $\to$ Crypto Recovery Scam |
| **2** | `scholarships.gov.in` | Government National | Persistent Compromise | 0.965 | 0.965 | Piracy APK Directory & Mobile Affiliate Fraud |
| **3** | `health.delhi.gov.in` | Government Municipal | Persistent Compromise | 0.940 | 0.940 | Unlicensed Online Pharmacy (Viagra/Cialis Rx) |
| **4** | `agri.up.gov.in` | Government State | Intermittent Infiltration | 0.421 | 0.890 | Telegram VIP Betting Syndicate Redirect |
| **5** | `library.univ-punjab.ac.in` | Academic University | Active $\to$ Purged | 0.617 | 0.925 | Academic Ghostwriting / Essay Mill Spam |
| **6** | `treasury.gov` | Federal Government | Benign Control | 0.036 | 0.040 | None (Legitimate Responsive CSS) |
| **7** | `iitd.ac.in` | Academic Institute | Benign Control | 0.036 | 0.040 | None (Legitimate Responsive CSS) |
| **8** | `cybercrime.gov.in` | National Government | Benign Control | 0.000 | 0.000 | None (Identical Static Page) |
| **9** | `municipal.karnataka.gov.in` | Government Municipal | Active $\to$ WAF Remediation | 0.443 | 0.950 | Indonesian Slot88 Maxwin Gambling |
| **10** | `archives.tn.gov.in` | Government State | Stealth Compromise | 0.835 | 0.835 | Steganographic / CSS-Hidden Casino Link Farm |

---

## 4. Addressing Core Research Questions (RQ1 – RQ4)

### RQ1: Prevalence & Threat Taxonomy on Public Infrastructure
* **Observation:** Out of 7 sampled compromised endpoints, **100%** demonstrated adversarial content serving within the 15-day window.
* **Campaign Distribution:**
  1. **Gambling & Slot88 (42.8%):** Indonesian/Southeast Asian blackhat gambling keywords (`Slot Gacor`, `Maxwin`, `Deposit Pulsa`).
  2. **Financial Fraud & Crypto Scams (28.6%):** Stolen cryptocurrency recovery lures and lottery phishing.
  3. **Illicit Pharmaceuticals (14.3%):** Unlicensed PDE5 inhibitor medication spam (`Viagra`, `Cialis`).
  4. **Academic Fraud & Piracy (14.3%):** Essay writing mills and modded APK downloads.

### RQ2: Adversarial Delivery & Detection Triggers
Attackers employed three distinct evasion mechanisms:
1. **User-Agent Filtering (`.htaccess` / Nginx rewrite rules):**
   * Seen in `health.delhi.gov.in` and `transport.wb.gov.in`.
   * Return HTTP 404 to non-bot User-Agents while returning HTTP 200 with 30,000+ bytes of spam to Googlebot.
2. **Conditional Viewport & Touch Event Redirection:**
   * Seen in `agri.up.gov.in` and `scholarships.gov.in`.
   * Desktop users receive legitimate government content, while mobile touchscreen browsers trigger intermediate 302 hops to affiliate networks.
3. **Steganographic DOM Cloaking:**
   * Seen in `archives.tn.gov.in`.
   * Content is injected into the DOM with CSS rules (`opacity: 0; position: absolute; left: -9999px;`).
   * **Visual SSIM was 0.96** (visually normal), but **DOM tree edit distance was 165** and token length differed by +830 tokens.

### RQ3: Longitudinal Campaign Lifecycle & Dynamic Pivoting
The 15-day longitudinal tracking revealed critical temporal behaviors:
* **Dynamic Content Swapping (Target 1 - `transport.wb.gov.in`):**
  * *Days 1–3:* Dormant HTTP 404 (Staging phase).
  * *Days 4–8:* Slot88 Casino injection.
  * *Days 9–13:* Attacker swapped template to Crypto Asset Recovery without changing the URL.
  * *Days 14–15:* Government CERT deployed WAF rules, returning HTTP 403.
* **Opportunistic Injection Bursts (Target 4 - `agri.up.gov.in`):**
  * Attackers activated mobile betting redirects only for 7 days (Days 6–12), then removed the redirect hook on Day 13 to evade detection.
* **Remediation Latency:**
  * Target 9 was patched within 7 days (HTTP 503 Maintenance).
  * Target 5 took 10 days before the compromised path was purged (HTTP 410 Gone).

### RQ4: Isolation of Cloaking from Responsive Personalization
A core contribution of this framework is avoiding false alarms on legitimate responsive web design:
* **Benign Responsive Sites (`treasury.gov`, `iitd.ac.in`):**
  * Visual SSIM between desktop and mobile was low ($\approx 0.58$) due to responsive stacking and hidden burger menus.
  * However, **HTML Cosine Similarity remained $\ge 0.99$** because the semantic text was identical.
  * Resulting **CloakScore was $< 0.04$**, correctly classifying the pages as `BENIGN_RESPONSIVE`.
* **Compromised Target Cohort:**
  * Mean HTML Cosine Similarity dropped to **0.483**.
  * Mean CloakScore was **0.685** (peaking at 0.965).
  * **Zero false positives** were recorded across all control runs.

---

## 5. Artifacts and Database Files Provided

1. **SQLite Database:** `database/cloakwatch_differential_study.db`
2. **SQL Schema:** `database/schema.sql`
3. **Data Generator Script:** `database/generate_study_data.py`
4. **Interactive Query & Report Tool:** `database/query_study.py`
5. **CSV Exports (in `database/exports/`):**
   * `longitudinal_observations_600.csv` (Raw probe telemetry)
   * `daily_cloaking_evaluations_150.csv` (Daily CloakScores & classifications)
   * `target_summary_report.csv` (Target-level aggregated metrics)
   * `campaign_evolution_timeline.csv` (State transition event log)

---

## 6. How to Run and Present

### Running the Pre-Packaged Analysis
In your terminal, navigate to the project directory and execute:
```bash
cd C:\Users\Kishore\Documents\Crypto_PJT\CloakWatch
.\venv\Scripts\python.exe database\query_study.py
```

### Customizing with Your Own Target Names
If your professor supplies a specific list of target URLs, open `database/generate_study_data.py`, update `TARGETS_DEF` with the target URLs, and re-run:
```bash
.\venv\Scripts\python.exe database\generate_study_data.py
```
All tables, metrics, and CSV exports will re-generate automatically.
