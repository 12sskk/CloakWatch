import subprocess
import sys
import json
import os
import shutil
from collections import defaultdict

def run_crawler(urls, out_dir):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    crawler_path = os.path.join(script_dir, 'crawler.py')
    cmd = [sys.executable, crawler_path]
    for url in urls:
        cmd.extend(['--url', url])
    cmd.extend(['--out-dir', out_dir])
    subprocess.run(cmd, check=True)

def analyze_observations(out_dir):
    obs_file = os.path.join(out_dir, 'observations.jsonl')
    results = defaultdict(dict)
    if not os.path.exists(obs_file):
        return results
        
    with open(obs_file, 'r') as f:
        for line in f:
            obs = json.loads(line)
            url = obs['url']
            label = obs['profile_label']
            results[url][label] = obs['html_sha256']
    return results

def print_summary(results, run_name):
    print(f"\n--- Summary Table ({run_name}) ---")
    print(f"{'URL':<35} | {'Profile':<20} | {'HTML SHA256'}")
    print("-" * 100)
    for url, profiles in results.items():
        for label, sha in profiles.items():
            print(f"{url:<35} | {label:<20} | {sha}")
        
        # Check diffs
        hashes = set(profiles.values())
        if len(hashes) > 1:
            print(f" -> RESULT: Differences found across profiles (Potential Cloaking) for {url}")
        else:
            print(f" -> RESULT: All profiles match for {url}")
        print("-" * 100)

def main():
    urls = [
        'http://localhost:5000/cloaked',
        'http://localhost:5000/responsive',
        'http://localhost:5000/static'
    ]
    
    print("Running validation script...")
    
    # Run 1
    out_dir_1 = './validate_data_run1'
    if os.path.exists(out_dir_1):
        shutil.rmtree(out_dir_1)
    run_crawler(urls, out_dir_1)
    results_1 = analyze_observations(out_dir_1)
    print_summary(results_1, "Run 1")
    
    # Run 2
    out_dir_2 = './validate_data_run2'
    if os.path.exists(out_dir_2):
        shutil.rmtree(out_dir_2)
    run_crawler(urls, out_dir_2)
    results_2 = analyze_observations(out_dir_2)
    
    print("\n--- Determinism Check ---")
    all_stable = True
    for url in urls:
        for label in results_1.get(url, {}):
            hash1 = results_1[url].get(label)
            hash2 = results_2.get(url, {}).get(label)
            if hash1 != hash2:
                print(f"MISMATCH for {url} with {label}: {hash1} vs {hash2}")
                all_stable = False
                
    if all_stable:
        print("SUCCESS: Hashes are stable/identical across runs.")
    else:
        print("WARNING: Some hashes were not stable across runs.")

if __name__ == '__main__':
    main()
