import json
import time
from urllib.parse import urlparse

import requests
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

from modules.clickjack_checker import check_clickjacking
from modules.headers_analyzer import analyze_headers
from modules.score_calculator import calculate_score
from modules.ssl_checker import check_ssl
from modules.tracker_detector import detect_trackers

app = Flask(__name__, static_folder="static", template_folder="static")
CORS(app)

HEADERS_TO_SEND = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def normalize_url(url: str) -> str:
    """Ensure URL has a scheme."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/audit", methods=["POST"])
def audit():
    data = request.get_json(force=True)
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    url = normalize_url(raw_url)

    # Validate URL
    parsed = urlparse(url)
    if not parsed.netloc:
        return jsonify({"error": "Invalid URL"}), 400

    start = time.time()

    # --- Fetch the page ---
    html = ""
    response_headers = {}
    fetch_error = None
    status_code = None

    try:
        resp = requests.get(
            url,
            headers=HEADERS_TO_SEND,
            timeout=15,
            allow_redirects=True,
            verify=True,
        )
        html = resp.text
        response_headers = dict(resp.headers)
        status_code = resp.status_code
        # Use final URL after redirects
        url = resp.url
    except requests.exceptions.SSLError as e:
        fetch_error = f"SSL Error: {str(e)[:200]}"
        # Try without verify for analysis purposes
        try:
            resp = requests.get(
                url, headers=HEADERS_TO_SEND, timeout=15, verify=False
            )
            html = resp.text
            response_headers = dict(resp.headers)
            status_code = resp.status_code
        except Exception:
            pass
    except Exception as e:
        fetch_error = str(e)[:300]

    # --- Run analysis modules ---
    ssl_result = check_ssl(url)
    headers_result = analyze_headers(response_headers)
    tracker_result = detect_trackers(html, response_headers, url)
    clickjack_result = check_clickjacking(response_headers)
    score_result = calculate_score(ssl_result, headers_result, tracker_result, clickjack_result)

    elapsed = round(time.time() - start, 2)

    return jsonify(
        {
            "url": url,
            "status_code": status_code,
            "fetch_error": fetch_error,
            "elapsed_seconds": elapsed,
            "ssl": ssl_result,
            "headers": headers_result,
            "trackers": tracker_result,
            "clickjacking": clickjack_result,
            "score": score_result,
        }
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
