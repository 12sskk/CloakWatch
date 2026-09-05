# Cybersec-Research
# CloakWatch
### An Internet-Scale Measurement Platform for Detecting and Characterizing Cloaked SEO Abuse on Compromised Government Websites

> **Research Goal:** Build a large-scale cybersecurity measurement platform capable of detecting, monitoring, and analyzing cloaked SEO spam campaigns hosted on compromised government websites.

---

# Overview

Government websites are increasingly being compromised and abused to host malicious SEO spam campaigns. Attackers exploit the reputation of trusted government domains to manipulate search engine rankings while hiding malicious content from normal users.

A common attack pattern includes:

```
Googlebot
        ↓
FitGirl / Steam / Play Store Page

Normal User
        ↓
404 Page

Later
        ↓
Casino Website

Later
        ↓
Crypto Scam

Later
        ↓
Pharmacy Spam
```

Traditional website scanners typically inspect pages from a single browser perspective. As a result, they fail to detect **differential content serving (cloaking)** where search engine crawlers and normal users receive different content.

---

# Setup & Execution (Phase 1 & Phase 2)

This repository includes a controlled test environment (Phase 1) and a minimal multi-profile crawler (Phase 2).

## Prerequisites
- **Python 3.12** or another stable Python version is strongly recommended. (Note: Playwright's `greenlet` dependency currently lacks pre-built wheels for pre-release versions like Python 3.14, which will require C++ build tools if used).

## Setup Instructions

1. **Create and activate a virtual environment (Recommended)**:
   ```bash
   py -3.12 -m venv venv
   ```

2. **Install dependencies**:
   ```bash
   .\venv\Scripts\pip.exe install -r requirements.txt
   .\venv\Scripts\playwright.exe install chromium
   ```

## Phase 1: Test Server

The test server simulates various cloaking and personalization scenarios.

Start the test server (runs on port 5000 by default):

```bash
cd test_server
..\venv\Scripts\python.exe app.py
```

Routes available:
- `http://localhost:5000/cloaked` - Ground truth for cloaking (different content based on User-Agent)
- `http://localhost:5000/responsive` - Legitimate responsive design (same content, different layout)
- `http://localhost:5000/static` - Control route (always identical)

Logs of all incoming requests are written to `test_server/test_server_log.jsonl`.

## Phase 2: Crawler

The crawler runs deterministic capture across multiple profiles to detect cloaking.

Run the validation script to test the crawler against the local test server (ensure the test server is running in a separate terminal first):

```bash
cd crawler
..\venv\Scripts\python.exe validate.py
```

The validation script will:
1. Crawl all 3 test routes with all 4 profiles (defined in `profiles.json`).
2. Produce a summary table indicating which pages show cloaking signals based on HTML SHA-256 differences.
3. Re-run the entire crawl to verify determinism and ensure hashes match across identical runs.

Artifacts (screenshots and HTML) and observations (`observations.jsonl`) are saved in the `validate_data_run1` and `validate_data_run2` directories when using `validate.py`. You can also run `crawler.py` directly to specify custom URLs.

---

# Vision

Rather than building another website scanner, **CloakWatch** aims to become an **Internet-scale cyber threat intelligence platform** capable of:

- Detecting cloaked SEO abuse
- Monitoring campaign evolution
- Identifying attacker infrastructure
- Building longitudinal datasets
- Supporting cybersecurity research and incident response

---

# Research Objectives

- Detect cloaked SEO spam on compromised government websites.
- Measure how frequently cloaking occurs.
- Analyze how attacker campaigns evolve over time.
- Discover shared infrastructure among campaigns.
- Build a reproducible dataset for future cybersecurity research.

---

# Research Questions

### RQ1

How common is cloaked SEO spam on government websites?

---

### RQ2

What techniques are used to distinguish search engine crawlers from normal users?

---

### RQ3

How do cloaked SEO campaigns evolve over time?

---

### RQ4

Can differential crawling accurately detect cloaking automatically?

---

# Proposed Contributions

The research will contribute five major components.

---

## Contribution 1 — Large-Scale Dataset

Instead of simply reporting:

> "We found 50 compromised government websites."

The platform will build:

> **The first longitudinal dataset of cloaked SEO abuse on compromised government websites.**

The dataset will contain:

- HTML snapshots
- DOM trees
- JavaScript
- Screenshots
- Redirect chains
- HTTP headers
- TLS metadata
- Crawl timestamps
- Campaign labels
- Infrastructure metadata

---

## Contribution 2 — Differential Measurement Framework

Each webpage will be analyzed from multiple perspectives.

Measurements include:

- HTML similarity
- DOM similarity
- JavaScript behavior
- HTTP headers
- TLS information
- Cookies
- Redirect chains
- Timing behavior
- Visual similarity
- Resource loading

Rather than comparing only HTML, each webpage becomes a multidimensional fingerprint.

---

## Contribution 3 — CloakScore

Instead of using simple rules like:

```
IF HTML differs

↓

Page is cloaked
```

Develop a novel detection metric called **CloakScore**.

Example feature vector:

```
HTML Similarity
DOM Similarity
Visual Similarity
Redirect Similarity
JavaScript Similarity
HTTP Header Distance
Cookie Differences
Timing Differences
TLS Differences
External Resource Differences
```

The detection model outputs:

```
Probability(Page is Cloaked)
```

instead of a binary decision.

This becomes the primary technical contribution of the research.

---

## Contribution 4 — Campaign Evolution Analysis

Rather than detecting a single cloaked page, CloakWatch continuously monitors websites.

Example timeline:

```
July 1
↓

404

↓

July 10

↓

Piracy

↓

July 18

↓

Casino

↓

July 25

↓

Crypto Scam

↓

August 2

↓

Removed
```

Tracking thousands of websites over months enables longitudinal measurement studies.

---

## Contribution 5 — Infrastructure Correlation

Instead of analyzing pages individually, identify relationships between campaigns.

Example:

```
Government Website A
        │
        │ Same JavaScript
        │
Government Website B
        │
        │ Same Redirect
        │
Government Website C
        │
        │ Same Affiliate ID
        │
Government Website D
```

This allows the discovery of attacker campaigns rather than isolated incidents.

---

# Platform Architecture

```
                    CloakWatch Platform
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   Data Collection    Measurement Engine   Intelligence Layer
        │                  │                  │
        │                  │                  │
   URL Discovery      Multi-Profile Crawl   CloakScore Engine
        │                  │                  │
        │                  │                  │
        │             Differential Engine     ML Detection
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                  Campaign Evolution Engine
                           │
                  Infrastructure Correlation
                           │
                    Threat Intelligence
                           │
                     Visualization Portal
```

---

# Core Modules

## URL Discovery

Collect candidate URLs from:

- Search engine results
- Public security reports
- CERT advisories
- Security blogs
- Threat intelligence feeds

Supported domains:

```
.gov
.gov.in
.nic.in
.edu
.ac.in
```

---

## Differential Crawling Engine

Each webpage is visited using multiple browsing profiles.

### Browser Profile

- Chrome
- Firefox
- Edge

### Measurement Profile

A controlled profile designed for comparative measurement without violating policies or misrepresenting identity.

Captured information:

- HTML
- DOM
- JavaScript
- Cookies
- Headers
- Redirects
- Screenshots
- TLS metadata

---

## Differential Analysis Engine

Compares observations using:

### HTML

- Cosine Similarity
- Levenshtein Distance
- Jaccard Similarity

### DOM

- Tree Comparison
- Hidden Elements
- Injected Scripts

### Screenshot

- SSIM
- Perceptual Hash
- Difference Hash

### JavaScript

Detect:

- navigator.userAgent
- document.referrer
- window.location
- Bot detection logic

### Redirect Analysis

Compare redirect chains between browsing profiles.

---

## Cloaking Detection Engine

### Rule-Based Detection

Example:

```
HTML Similarity < Threshold

AND

Visual Similarity < Threshold

AND

Redirect Chains Differ

↓

Potential Cloaking
```

### Machine Learning Detection

Possible models:

- Random Forest
- XGBoost
- Isolation Forest

Features include:

- HTML distance
- DOM distance
- JavaScript metrics
- Redirect count
- Cookie differences
- Status codes
- Response length
- Screenshot similarity

---

## Campaign Classification

Automatically categorize malicious content.

Categories include:

- Piracy
- Casino
- Cryptocurrency Scam
- Pharmacy Spam
- Fake APK
- Fake Shopping
- Streaming
- Lottery

Potential approaches:

- TF-IDF
- BERT
- Transformer models
- Keyword extraction

---

## Infrastructure Analysis

Extract infrastructure indicators:

- Analytics IDs
- Affiliate IDs
- JavaScript URLs
- CDN
- Hosting
- IP Address
- TLS Certificates

Cluster related websites based on shared infrastructure.

---

## Timeline Engine

Repeated measurements enable campaign evolution analysis.

```
404

↓

Piracy

↓

Casino

↓

Crypto Scam

↓

Offline
```

---

## Threat Intelligence Dashboard

Provide investigators with:

- Country
- Government Department
- Website
- Campaign Timeline
- Infrastructure Cluster
- Detection Confidence
- Screenshots
- HTML Differences
- JavaScript Differences
- Redirect Chains

Designed to support CERT teams and cybersecurity researchers.

---

# Project Structure

```
cloakwatch/

│
├── collector/
│   ├── url_discovery/
│   ├── scheduler/
│   └── crawler/
│
├── analyzer/
│   ├── html/
│   ├── dom/
│   ├── javascript/
│   ├── screenshot/
│   ├── redirect/
│   ├── headers/
│   └── tls/
│
├── detector/
│   ├── cloakscore/
│   ├── heuristics/
│   └── ml/
│
├── infrastructure/
│   ├── clustering/
│   ├── graph/
│   └── attribution/
│
├── timeline/
│
├── dashboard/
│
├── api/
│
├── database/
│
├── datasets/
│
├── experiments/
│
├── notebooks/
│
└── papers/
```

---

# Technology Stack

## Crawling

- Playwright
- Selenium
- Requests
- BeautifulSoup

## Analysis

- BeautifulSoup
- OpenCV
- imagehash
- NetworkX
- scikit-learn

## Machine Learning

- XGBoost
- Random Forest
- Isolation Forest
- Transformers

## Database

- PostgreSQL
- MongoDB

## Dashboard

- Streamlit
- Plotly
- Grafana

---

# Experimental Evaluation

Planned experiments include:

### Experiment 1

Can CloakWatch detect cloaking earlier than existing scanners?

---

### Experiment 2

Which features contribute most to detection accuracy?

---

### Experiment 3

How rapidly do campaigns evolve?

---

### Experiment 4

How many infrastructure clusters exist?

---

### Experiment 5

Can infrastructure clusters predict future compromises?

---

# Research Roadmap

## Phase 1

- Literature Review
- Research Gap Analysis
- Architecture Design
- Ethical Review

---

## Phase 2

- Platform Development
- Differential Crawling
- Database Design
- Dashboard Prototype

---

## Phase 3

- Large-scale Data Collection
- Longitudinal Monitoring
- Dataset Construction

---

## Phase 4

- CloakScore Development
- Machine Learning Evaluation
- Infrastructure Analysis
- Paper Writing

---

# Expected Impact

CloakWatch aims to move beyond traditional website scanning by providing a comprehensive measurement platform for understanding cloaked SEO abuse on compromised public-sector websites.

The project seeks to contribute:

- A reproducible longitudinal dataset
- A novel cloaking detection methodology
- Infrastructure correlation techniques
- Campaign evolution analysis
- Practical insights for researchers, CERT teams, and defenders

---

# Ethical Considerations

This project is intended for **defensive cybersecurity research**.

Key principles include:

- Observe publicly accessible content only.
- Avoid actions that could harm target websites or violate terms of service.
- Do not exploit vulnerabilities or gain unauthorized access.
- Respect robots.txt and applicable policies where appropriate.
- Consider responsible disclosure if active compromises are identified.
- Publish only aggregated results or sanitized indicators where necessary to avoid facilitating abuse.

---

# License

This project is currently under active research and is intended for academic and defensive cybersecurity purposes.
