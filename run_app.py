#!/usr/bin/env python3
"""
CloakWatch: Interactive Threat Scanner & Excel Export Application Launcher
Run this script to start the web dashboard at http://127.0.0.1:5000
"""

import os
import sys

# Ensure project root is in path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from web_app.app import app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("\n" + "=" * 65)
    print("  CLOAKWATCH: INTERACTIVE THREAT SCANNER & EXCEL EXPORTER")
    print(f"  Dashboard URL: http://127.0.0.1:{port}")
    print("  Open this URL in your browser to post URLs and export Excel")
    print("=" * 65 + "\n")
    app.run(host="127.0.0.1", port=port, debug=False)
