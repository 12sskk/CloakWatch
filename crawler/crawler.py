import argparse
import json
import os
import datetime
import hashlib
from urllib.parse import urlparse
import re
from playwright.sync_api import sync_playwright

def get_url_safe_slug(url):
    parsed = urlparse(url)
    slug = f"{parsed.netloc}{parsed.path}"
    slug = re.sub(r'[^a-zA-Z0-9]', '_', slug)
    return slug

def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()

def crawl_url_with_profile(url, profile, out_dir, p):
    label = profile['label']
    timestamp = datetime.datetime.utcnow().isoformat()
    safe_slug = get_url_safe_slug(url)
    
    artifact_dir = os.path.join(out_dir, 'artifacts', safe_slug, label)
    os.makedirs(artifact_dir, exist_ok=True)
    
    file_ts = timestamp.replace(':', '-').replace('.', '-')
    html_path = os.path.join(artifact_dir, f"{file_ts}.html")
    screenshot_path = os.path.join(artifact_dir, f"{file_ts}.png")
    
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(
        user_agent=profile['user_agent'],
        viewport=profile['viewport']
    )
    page = context.new_page()
    
    start_time = datetime.datetime.now()
    
    redirect_chain = []
    
    def handle_response(response):
        if response.request.resource_type == "document":
            redirect_chain.append({
                "url": response.url,
                "status": response.status
            })
            
    page.on("response", handle_response)
    
    try:
        response = page.goto(url, wait_until='networkidle')
        end_time = datetime.datetime.now()
        
        status_code = response.status if response else 0
        final_url = page.url
        headers = response.headers if response else {}
        
        try:
            body = response.body()
            response_size_bytes = len(body)
        except Exception:
            response_size_bytes = 0
            
        response_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        html_content = page.content()
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        page.screenshot(path=screenshot_path, full_page=True)
        
        with open(screenshot_path, 'rb') as f:
            screenshot_bytes = f.read()
            
        html_hash = sha256(html_content)
        screenshot_hash = sha256(screenshot_bytes)
        
        observation = {
            "timestamp": timestamp,
            "url": url,
            "profile_label": label,
            "status_code": status_code,
            "final_url": final_url,
            "response_time_ms": response_time_ms,
            "response_size_bytes": response_size_bytes,
            "html_path": html_path,
            "screenshot_path": screenshot_path,
            "html_sha256": html_hash,
            "screenshot_sha256": screenshot_hash,
            "redirect_chain": redirect_chain
        }
        
        obs_file = os.path.join(out_dir, 'observations.jsonl')
        with open(obs_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(observation) + '\n')
            
    except Exception as e:
        print(f"Error crawling {url} with profile {label}: {e}")
    finally:
        context.close()
        browser.close()

def main():
    parser = argparse.ArgumentParser(description="Minimal Multi-Profile Crawler")
    parser.add_argument('--url', action='append', required=True, help="URL to crawl (can be specified multiple times)")
    parser.add_argument('--profiles', default='all', help="Comma separated list of profiles or 'all'")
    parser.add_argument('--out-dir', default='./data', help="Output directory")
    args = parser.parse_args()
    
    # Resolve absolute path to profiles.json
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profiles_path = os.path.join(script_dir, 'profiles.json')
    
    with open(profiles_path, 'r') as f:
        all_profiles = json.load(f)
        
    if args.profiles == 'all':
        profiles_to_run = all_profiles.values()
    else:
        profile_names = args.profiles.split(',')
        profiles_to_run = [all_profiles[name] for name in profile_names if name in all_profiles]
        
    os.makedirs(args.out_dir, exist_ok=True)
    
    with sync_playwright() as p:
        for url in args.url:
            for profile in profiles_to_run:
                print(f"Crawling {url} with {profile['label']}...")
                crawl_url_with_profile(url, profile, args.out_dir, p)

if __name__ == "__main__":
    main()
