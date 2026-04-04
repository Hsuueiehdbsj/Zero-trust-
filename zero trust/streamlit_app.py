import time
from urllib.parse import urlparse

import requests
import streamlit as st

from modules.clickjack_checker import check_clickjacking
from modules.headers_analyzer import analyze_headers
from modules.score_calculator import calculate_score
from modules.ssl_checker import check_ssl
from modules.tracker_detector import detect_trackers

st.set_page_config(
    page_title="Zero-Trust Privacy Auditor",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

st.title("🛡️ Zero-Trust Privacy Auditor")
st.markdown("Analyze the security posture and privacy hygiene of any website.")

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

with st.form(key='audit_form'):
    url_input = st.text_input("Enter a Website URL to Audit", placeholder="example.com")
    submit_button = st.form_submit_button(label='Run Audit')

if submit_button:
    if not url_input:
        st.error("Please enter a valid URL.")
    else:
        url = normalize_url(url_input)
        parsed = urlparse(url)
        if not parsed.netloc:
            st.error("Invalid URL format.")
        else:
            with st.spinner(f"Auditing {url}..."):
                start = time.time()

                # Fetch page
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
                    url = resp.url
                except requests.exceptions.SSLError as e:
                    fetch_error = f"SSL Error: {str(e)[:200]}"
                    try:
                        resp = requests.get(url, headers=HEADERS_TO_SEND, timeout=15, verify=False)
                        html = resp.text
                        response_headers = dict(resp.headers)
                        status_code = resp.status_code
                    except Exception:
                        pass
                except Exception as e:
                    fetch_error = str(e)[:300]

                # Run modules if fetch partially succeeded
                ssl_result = check_ssl(url)
                headers_result = analyze_headers(response_headers)
                tracker_result = detect_trackers(html, response_headers, url)
                clickjack_result = check_clickjacking(response_headers)
                score_result = calculate_score(ssl_result, headers_result, tracker_result, clickjack_result)

                elapsed = round(time.time() - start, 2)

            if fetch_error:
                st.warning(f"Note: Fetched with warning: {fetch_error}")
            
            # --- Results Display ---
            score = score_result.get("score", 0)
            st.markdown("---")
            col_score, col_status, col_time = st.columns(3)
            col_score.metric("Privacy Score", f"{score}/100")
            col_status.metric("HTTP Status", status_code if status_code else "N/A")
            col_time.metric("Scan Time", f"{elapsed}s")

            # Score Breakdown
            st.subheader("Analysis Breakdown")
            
            # SSL
            with st.expander("SSL/TLS Security", expanded=True):
                if ssl_result.get("valid"):
                    st.success("✅ Valid SSL Certificate")
                    st.write(f"Issuer: {ssl_result.get('issuer', 'Unknown')}")
                    st.write(f"Expires in {ssl_result.get('days_remaining', 0)} days.")
                else:
                    st.error(f"❌ SSL Issue: {ssl_result.get('error', 'Unknown Error')}")
            
            # Headers
            with st.expander("Security Headers", expanded=True):
                st.write(f"Found {headers_result.get('score_context', {}).get('found')} / 3 recommended headers.")
                for header, info in headers_result.get("evaluations", {}).items():
                    if info["present"]:
                        st.success(f"✅ {header} is present.")
                    else:
                        st.error(f"❌ Missing {header}. ({info['description']})")

            # Trackers
            with st.expander("Trackers & Cookies", expanded=True):
                trackers_found = tracker_result.get("trackers_found", [])
                st.write(f"Detected **{tracker_result.get('count', 0)}** trackers.")
                if trackers_found:
                    st.warning(", ".join(trackers_found))
                else:
                    st.success("No known third-party trackers detected.")

            # Clickjacking
            with st.expander("Clickjacking Vulnerability", expanded=True):
                if clickjack_result.get("vulnerable"):
                    st.error("❌ Vulnerable to Clickjacking")
                    st.write(clickjack_result.get("details"))
                else:
                    st.success("✅ Protected against Clickjacking")
                    st.write(clickjack_result.get("details"))

