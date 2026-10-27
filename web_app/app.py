import os
import sys
import json
import datetime
from flask import Flask, render_template, request, jsonify, send_file

# Add project root to sys.path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from web_app.scanner import analyze_urls
from web_app.excel_exporter import build_excel_report

app = Flask(__name__, template_folder="templates")
app.config['SECRET_KEY'] = 'cloakwatch-cybersec-research-2026'

# In-memory session store for latest scan results
LATEST_SCAN = {
    "timestamp": None,
    "results": []
}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json() or {}
    urls = data.get("urls", [])
    live_crawl = data.get("live_crawl", True)

    if not urls:
        return jsonify({"status": "error", "message": "No URLs provided"}), 400

    print(f"[*] Received scan request for {len(urls)} URLs (live_crawl={live_crawl})")
    try:
        results = analyze_urls(urls, live_crawl=live_crawl)
        
        # Save to memory cache
        LATEST_SCAN["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        LATEST_SCAN["results"] = results
        
        return jsonify({
            "status": "success",
            "count": len(results),
            "timestamp": LATEST_SCAN["timestamp"],
            "results": results
        })
    except Exception as e:
        print(f"[-] Scan error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/api/export/excel", methods=["GET"])
def export_excel():
    if not LATEST_SCAN["results"]:
        # Fallback to loading sample from study database if user directly hits export
        from web_app.scanner import analyze_urls
        default_samples = [
            "https://employment.ap.gov.in/online-fitgirl-repack-apk-11219t52.html",
            "https://urjapay.andamannicobar.gov.in/aviator/yes-spin-game-login-download-and-mobile-access-on-android/",
            "https://suvidha.mahaonline.gov.in/apps-kalyani-challenging-figure.html",
            "https://wb.gov.in/online-imagica-theme-park-82803t47",
            "https://cybercrime.gov.in/static/awareness.html",
            "https://www.treasury.gov/resource-center/data-chart"
        ]
        results = analyze_urls(default_samples, live_crawl=False)
        LATEST_SCAN["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        LATEST_SCAN["results"] = results

    ts_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"CloakWatch_Threat_Report_{ts_str}.xlsx"
    
    meta = {
        "timestamp": LATEST_SCAN["timestamp"],
        "mode": "Multi-Persona Probing (P1 Desktop, P2 Mobile, P3 Googlebot, P4 Mobile Bot)"
    }
    
    excel_stream = build_excel_report(LATEST_SCAN["results"], scan_meta=meta)
    
    return send_file(
        excel_stream,
        as_attachment=True,
        download_name=filename,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n=======================================================")
    print(f"  CLOAKWATCH INTERACTIVE SCANNER & THREAT DASHBOARD")
    print(f"  Serving at: http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="127.0.0.1", port=port, debug=False)
