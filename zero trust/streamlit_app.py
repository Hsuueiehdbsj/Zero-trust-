import time
from urllib.parse import urlparse

import requests
import streamlit as st

from modules.clickjack_checker import check_clickjacking
from modules.headers_analyzer import analyze_headers
from modules.score_calculator import calculate_score
from modules.ssl_checker import check_ssl
from modules.tracker_detector import detect_trackers

# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Zero-Trust Privacy Auditor",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS ─────────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* Import font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    /* Grade badge */
    .grade-badge {
        display: inline-block;
        font-size: 3.5rem;
        font-weight: 700;
        width: 90px;
        height: 90px;
        line-height: 90px;
        text-align: center;
        border-radius: 50%;
        color: white;
        box-shadow: 0 4px 20px rgba(0,0,0,0.25);
        margin: 0 auto;
    }
    .grade-A { background: linear-gradient(135deg, #22c55e, #16a34a); }
    .grade-B { background: linear-gradient(135deg, #84cc16, #65a30d); }
    .grade-C { background: linear-gradient(135deg, #eab308, #ca8a04); }
    .grade-D { background: linear-gradient(135deg, #f97316, #ea580c); }
    .grade-F { background: linear-gradient(135deg, #ef4444, #dc2626); }

    /* Score bar */
    .score-bar-bg {
        background: #e5e7eb;
        border-radius: 999px;
        height: 12px;
        width: 100%;
    }
    .score-bar-fill {
        height: 12px;
        border-radius: 999px;
    }

    /* Tracker chip */
    .tracker-chip {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 999px;
        font-size: 0.78rem;
        font-weight: 500;
        margin: 2px;
        background: #fef3c7;
        color: #92400e;
        border: 1px solid #fde68a;
    }
    .cookie-chip-secure { background:#dcfce7; color:#166534; border:1px solid #bbf7d0; }
    .cookie-chip-warn   { background:#fef9c3; color:#713f12; border:1px solid #fde68a; }
    .cookie-chip-bad    { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown("## 🛡️ Zero-Trust Privacy Auditor")
st.caption("Analyze the security posture and privacy hygiene of any website.")

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
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def score_color(score: int) -> str:
    if score >= 80:
        return "#22c55e"
    elif score >= 60:
        return "#84cc16"
    elif score >= 40:
        return "#eab308"
    elif score >= 20:
        return "#f97316"
    return "#ef4444"


# ── Input form ─────────────────────────────────────────────────────────────────
with st.form(key="audit_form"):
    url_input = st.text_input(
        "🌐 Enter a Website URL",
        placeholder="e.g. example.com or https://example.com",
        label_visibility="visible",
    )
    submit = st.form_submit_button("🔍 Run Audit", use_container_width=True)

# ── Audit logic ────────────────────────────────────────────────────────────────
if submit:
    if not url_input.strip():
        st.error("Please enter a valid URL.")
        st.stop()

    url = normalize_url(url_input)
    parsed = urlparse(url)
    if not parsed.netloc:
        st.error("Invalid URL format. Please include a valid domain.")
        st.stop()

    with st.spinner(f"Auditing **{url}** — this may take up to 15 seconds…"):
        start = time.time()

        html = ""
        response_headers: dict = {}
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
            fetch_error = f"SSL Error encountered: {str(e)[:200]}"
            try:
                resp = requests.get(url, headers=HEADERS_TO_SEND, timeout=15, verify=False)
                html = resp.text
                response_headers = dict(resp.headers)
                status_code = resp.status_code
            except Exception:
                pass
        except Exception as e:
            fetch_error = str(e)[:300]

        ssl_result      = check_ssl(url)
        headers_result  = analyze_headers(response_headers)
        tracker_result  = detect_trackers(html, response_headers, url)
        clickjack_result = check_clickjacking(response_headers)
        score_result    = calculate_score(ssl_result, headers_result, tracker_result, clickjack_result)

        elapsed = round(time.time() - start, 2)

    if fetch_error:
        st.warning(f"⚠️ {fetch_error}")

    # ── Summary row ──────────────────────────────────────────────────────────
    st.markdown("---")
    score = score_result["score"]
    grade = score_result["grade"]
    color = score_result["grade_color"]

    col_grade, col_metrics = st.columns([1, 3])
    with col_grade:
        st.markdown(
            f'<div style="text-align:center;">'
            f'<div class="grade-badge grade-{grade}">{grade}</div>'
            f'<p style="text-align:center;margin-top:8px;font-weight:600;color:{color};">'
            f'Privacy Score<br><span style="font-size:1.6rem;">{score}/100</span></p>'
            f'</div>',
            unsafe_allow_html=True,
        )

    with col_metrics:
        m1, m2, m3 = st.columns(3)
        m1.metric("HTTP Status", status_code if status_code else "N/A")
        m2.metric("Trackers Found", tracker_result["tracker_count"])
        m3.metric("Scan Time", f"{elapsed}s")

        # Score bar
        bar_color = score_color(score)
        st.markdown(
            f'<div class="score-bar-bg"><div class="score-bar-fill" '
            f'style="width:{score}%; background:{bar_color};"></div></div>',
            unsafe_allow_html=True,
        )

    # ── Score breakdown ───────────────────────────────────────────────────────
    st.markdown("### 📊 Score Breakdown")
    for item in score_result["breakdown"]:
        item_score = item["score"]
        item_max   = item["max"]
        label      = item["category"]
        note       = item["note"]
        # display
        sign = "+" if item_score >= 0 else ""
        badge_color = "#22c55e" if item_score >= 0 else "#ef4444"
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:6px;">'
            f'<span style="font-weight:600;min-width:180px;">{label}</span>'
            f'<span style="color:{badge_color};font-weight:700;">{sign}{item_score}</span>'
            f'<span style="color:#6b7280;font-size:0.85rem;">/ {item_max} — {note}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("---")

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    with st.expander("🔒 SSL / TLS Security", expanded=True):
        if ssl_result.get("uses_https"):
            if ssl_result.get("cert_valid"):
                days = ssl_result.get("days_until_expiry")
                issuer = ssl_result.get("cert_issuer", "Unknown")
                expiry = ssl_result.get("cert_expiry", "N/A")

                st.success(f"✅ Valid HTTPS certificate")
                c1, c2, c3 = st.columns(3)
                c1.metric("Issuer", issuer)
                c2.metric("Expires", expiry)
                c3.metric("Days Remaining", days if days is not None else "N/A")

                if days is not None and days < 30:
                    st.warning(f"⚠️ Certificate expires in {days} days — renewal recommended soon.")
            else:
                st.error(f"❌ Certificate issue: {ssl_result.get('error', 'Unknown')}")
        else:
            st.error("❌ No HTTPS — the site uses plain HTTP.")
            if ssl_result.get("error"):
                st.caption(ssl_result["error"])

    # ── Security Headers ──────────────────────────────────────────────────────
    with st.expander("🧱 Security Headers", expanded=True):
        hdrs = headers_result.get("headers", {})
        found_count  = sum(1 for h in hdrs.values() if h["present"])
        total_headers = len(hdrs)
        st.write(f"Found **{found_count}** / {total_headers} recommended security headers.")

        for header_name, info in hdrs.items():
            sev = info.get("severity", "medium")
            sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(sev, "⚪")
            if info["present"]:
                st.success(f"✅ **{header_name}** — {info['description']}")
                if info.get("value"):
                    st.code(info["value"], language=None)
            else:
                st.error(f"{sev_icon} Missing **{header_name}** — {info['description']}")

    # ── Trackers & Cookies ────────────────────────────────────────────────────
    with st.expander("🕵️ Trackers & Cookies", expanded=True):
        trackers = tracker_result.get("trackers", [])
        cookies  = tracker_result.get("cookies", [])

        st.write(
            f"Detected **{tracker_result['tracker_count']}** third-party tracker(s) "
            f"and **{tracker_result['cookie_count']}** cookie(s)."
        )

        if trackers:
            st.markdown("**Trackers detected:**")
            chips = "".join(
                f'<span class="tracker-chip">🔍 {t["domain"]} <em>({t["category"]})</em></span>'
                for t in trackers
            )
            st.markdown(chips, unsafe_allow_html=True)
        else:
            st.success("✅ No known third-party trackers detected.")

        if cookies:
            st.markdown("**Cookies:**")
            for c in cookies:
                secure   = c.get("secure", False)
                httponly = c.get("httponly", False)
                samesite = c.get("samesite", "Not set")
                flags = []
                if secure:
                    flags.append('<span class="cookie-chip-secure">Secure</span>')
                else:
                    flags.append('<span class="cookie-chip-bad">Not Secure</span>')
                if httponly:
                    flags.append('<span class="cookie-chip-secure">HttpOnly</span>')
                else:
                    flags.append('<span class="cookie-chip-warn">No HttpOnly</span>')
                ss_cls = "cookie-chip-secure" if samesite.lower() in ("strict", "lax") else "cookie-chip-warn"
                flags.append(f'<span class="{ss_cls}">SameSite={samesite}</span>')

                st.markdown(
                    f'<p style="margin:4px 0;"><strong>{c["name"]}</strong> &nbsp;'
                    + " ".join(flags)
                    + "</p>",
                    unsafe_allow_html=True,
                )
        else:
            st.info("No cookies detected in response headers.")

    # ── Clickjacking ──────────────────────────────────────────────────────────
    with st.expander("🖱️ Clickjacking Vulnerability", expanded=True):
        status = clickjack_result.get("status", "LIKELY_VULNERABLE")
        label  = clickjack_result.get("label", "Unknown")
        details = clickjack_result.get("details", [])

        if status == "SAFE":
            st.success(f"✅ {label} — fully protected against clickjacking.")
        elif status == "PARTIAL":
            st.warning(f"⚠️ {label} — partial clickjacking protection.")
        else:
            st.error(f"❌ {label} — vulnerable to clickjacking attacks.")

        for line in details:
            st.markdown(f"- {line}")

    st.caption(f"Scan completed in {elapsed}s · Zero-Trust Privacy Auditor")
