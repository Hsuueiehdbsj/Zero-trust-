import os
from urllib.parse import urlparse

from bs4 import BeautifulSoup


def _load_tracker_domains() -> set:
    """Load the bundled tracker domain list."""
    tracker_file = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "data", "trackers.txt"
    )
    domains = set()
    if os.path.exists(tracker_file):
        with open(tracker_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    return domains


TRACKER_DOMAINS = _load_tracker_domains()

# Well-known tracker categories for labelling
TRACKER_CATEGORIES = {
    "google-analytics.com": "Analytics",
    "googletagmanager.com": "Tag Manager",
    "googlesyndication.com": "Advertising",
    "doubleclick.net": "Advertising",
    "facebook.net": "Social / Tracking",
    "connect.facebook.net": "Social / Tracking",
    "hotjar.com": "Session Recording",
    "clarity.ms": "Session Recording",
    "mixpanel.com": "Analytics",
    "amplitude.com": "Analytics",
    "fullstory.com": "Session Recording",
    "segment.com": "Data Pipeline",
    "intercom.io": "Customer Messaging",
    "drift.com": "Customer Messaging",
    "hubspot.com": "Marketing",
    "marketo.com": "Marketing",
    "criteo.com": "Advertising",
    "taboola.com": "Advertising",
    "outbrain.com": "Advertising",
    "scorecardresearch.com": "Analytics",
    "quantserve.com": "Analytics",
    "newrelic.com": "Performance Monitoring",
    "sentry.io": "Error Tracking",
    "optimizely.com": "A/B Testing",
    "vwo.com": "A/B Testing",
}


def _get_domain(url: str) -> str:
    """Extract root domain from a URL string."""
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        # Strip www.
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:]).lower()
        return hostname.lower()
    except Exception:
        return ""


def _is_tracker(domain: str) -> bool:
    """Check if a domain matches any known tracker."""
    if not domain:
        return False
    # Direct match
    if domain in TRACKER_DOMAINS:
        return True
    # Subdomain match: check if any tracker domain is a suffix
    for tracker in TRACKER_DOMAINS:
        if domain.endswith("." + tracker) or domain == tracker:
            return True
    return False


def _get_category(domain: str) -> str:
    for known, cat in TRACKER_CATEGORIES.items():
        if domain.endswith(known) or domain == known:
            return cat
    return "Tracker / Analytics"


def detect_trackers(html: str, response_headers: dict, page_url: str) -> dict:
    """
    Detect trackers and cookies from page HTML and response headers.
    Returns tracker list, cookie list, and summary counts.
    """
    soup = BeautifulSoup(html, "lxml")
    page_domain = _get_domain(page_url)

    found_trackers = {}

    # Check external scripts, images, iframes, links
    tags_attrs = [
        ("script", "src"),
        ("img", "src"),
        ("iframe", "src"),
        ("link", "href"),
    ]
    for tag, attr in tags_attrs:
        for element in soup.find_all(tag, **{attr: True}):
            src = element.get(attr, "")
            domain = _get_domain(src)
            if not domain or domain == page_domain:
                continue
            if _is_tracker(domain):
                if domain not in found_trackers:
                    found_trackers[domain] = {
                        "domain": domain,
                        "category": _get_category(domain),
                        "found_in": [],
                    }
                found_trackers[domain]["found_in"].append(f"<{tag}>")

    # Parse cookies from Set-Cookie headers
    cookies = []
    raw_cookies = response_headers.get("Set-Cookie", "") or response_headers.get(
        "set-cookie", ""
    )
    # requests stores multiple Set-Cookie in a single string separated by newlines sometimes
    if raw_cookies:
        for cookie_str in raw_cookies.split("\n"):
            cookie_str = cookie_str.strip()
            if not cookie_str:
                continue
            parts = [p.strip() for p in cookie_str.split(";")]
            name_val = parts[0].split("=", 1)
            name = name_val[0].strip() if name_val else "unknown"
            flags = [p.lower() for p in parts[1:]]
            cookies.append(
                {
                    "name": name,
                    "secure": any("secure" in f for f in flags),
                    "httponly": any("httponly" in f for f in flags),
                    "samesite": next(
                        (
                            p.split("=")[1].strip()
                            for p in parts[1:]
                            if "samesite" in p.lower()
                        ),
                        "Not set",
                    ),
                }
            )

    return {
        "trackers": list(found_trackers.values()),
        "tracker_count": len(found_trackers),
        "cookies": cookies,
        "cookie_count": len(cookies),
    }
