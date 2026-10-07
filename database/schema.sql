-- CloakWatch: Longitudinal Differential Measurement Database Schema
-- Designed for 15-Day Multi-Profile Monitoring of Compromised Domains

DROP TABLE IF EXISTS campaign_evolution;
DROP TABLE IF EXISTS cloaking_evaluations;
DROP TABLE IF EXISTS differential_pairs;
DROP TABLE IF EXISTS observations;
DROP TABLE IF EXISTS crawl_runs;
DROP TABLE IF EXISTS targets;

-- 1. Monitored Target Domains and URL Paths
CREATE TABLE targets (
    target_id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL CHECK(category IN ('GOVERNMENT_NATIONAL', 'GOVERNMENT_STATE', 'GOVERNMENT_MUNICIPAL', 'ACADEMIC', 'BENIGN_CONTROL')),
    jurisdiction TEXT NOT NULL,
    threat_profile TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Longitudinal Daily Crawl Cycles (15 Days)
CREATE TABLE crawl_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    day_index INTEGER NOT NULL CHECK(day_index BETWEEN 1 AND 15),
    scheduled_date DATE NOT NULL,
    total_targets INTEGER NOT NULL,
    completed_observations INTEGER NOT NULL,
    execution_status TEXT NOT NULL DEFAULT 'COMPLETED'
);

-- 3. Raw Individual Multi-Profile Probing Observations
CREATE TABLE observations (
    obs_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES crawl_runs(run_id),
    target_id INTEGER NOT NULL REFERENCES targets(target_id),
    day_index INTEGER NOT NULL,
    profile_label TEXT NOT NULL CHECK(profile_label IN ('P1_desktop_normal', 'P2_mobile_normal', 'P3_crawler_oriented', 'P4_mobile_crawler')),
    user_agent TEXT NOT NULL,
    viewport TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    final_url TEXT NOT NULL,
    redirect_count INTEGER NOT NULL DEFAULT 0,
    redirect_chain_json TEXT,
    response_time_ms INTEGER NOT NULL,
    response_size_bytes INTEGER NOT NULL,
    html_sha256 TEXT NOT NULL,
    screenshot_sha256 TEXT NOT NULL,
    page_title TEXT,
    text_token_count INTEGER NOT NULL,
    injected_spam_category TEXT CHECK(injected_spam_category IN ('NONE', 'CASINO_GAMBLING', 'PIRACY_APK', 'CRYPTO_SCAM', 'PHARMA_SPAM', 'ESSAY_WRITING')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 4. Pairwise Differential Measurements (e.g. Desktop Normal vs Googlebot Crawler)
CREATE TABLE differential_pairs (
    pair_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES crawl_runs(run_id),
    target_id INTEGER NOT NULL REFERENCES targets(target_id),
    day_index INTEGER NOT NULL,
    comparison_type TEXT NOT NULL CHECK(comparison_type IN ('desktop_vs_crawler', 'desktop_vs_mobile', 'crawler_vs_mobile_crawler')),
    obs_id_a INTEGER NOT NULL REFERENCES observations(obs_id),
    obs_id_b INTEGER NOT NULL REFERENCES observations(obs_id),
    status_code_divergence BOOLEAN NOT NULL,
    redirect_divergence BOOLEAN NOT NULL,
    html_cosine_similarity REAL NOT NULL CHECK(html_cosine_similarity BETWEEN 0.0 AND 1.0),
    html_jaccard_similarity REAL NOT NULL CHECK(html_jaccard_similarity BETWEEN 0.0 AND 1.0),
    dom_tree_edit_distance INTEGER NOT NULL,
    visual_ssim REAL NOT NULL CHECK(visual_ssim BETWEEN 0.0 AND 1.0),
    phash_hamming_distance INTEGER NOT NULL,
    header_distance_score REAL NOT NULL
);

-- 5. Daily Aggregated Cloaking Evaluation & Scoring
CREATE TABLE cloaking_evaluations (
    eval_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES crawl_runs(run_id),
    target_id INTEGER NOT NULL REFERENCES targets(target_id),
    day_index INTEGER NOT NULL,
    cloak_score REAL NOT NULL CHECK(cloak_score BETWEEN 0.0 AND 1.0),
    classification TEXT NOT NULL CHECK(classification IN ('CLOAKED_SEO_SPAM', 'CLOAKED_CONDITIONAL_REDIRECT', 'BENIGN_RESPONSIVE', 'BENIGN_STATIC', 'DORMANT_OR_OFFLINE', 'REMEDIATED')),
    primary_signal TEXT NOT NULL,
    detected_campaign TEXT NOT NULL,
    confidence_level TEXT NOT NULL CHECK(confidence_level IN ('HIGH', 'MEDIUM', 'LOW'))
);

-- 6. Longitudinal Campaign Lifecycle & State Transitions
CREATE TABLE campaign_evolution (
    evolution_id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL REFERENCES targets(target_id),
    start_day INTEGER NOT NULL,
    end_day INTEGER NOT NULL,
    observed_state TEXT NOT NULL,
    active_campaign TEXT NOT NULL,
    transition_trigger TEXT NOT NULL,
    notes TEXT
);

-- Create Indices for High-Performance Queries
CREATE INDEX idx_obs_target_day ON observations(target_id, day_index);
CREATE INDEX idx_diff_target_day ON differential_pairs(target_id, day_index);
CREATE INDEX idx_eval_target_day ON cloaking_evaluations(target_id, day_index);
