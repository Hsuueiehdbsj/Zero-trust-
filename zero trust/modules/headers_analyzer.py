SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "points": 15,
        "description": "Forces HTTPS connections (HSTS)",
        "severity": "high",
    },
    "Content-Security-Policy": {
        "points": 20,
        "description": "Controls resource loading to prevent XSS",
        "severity": "critical",
    },
    "X-Frame-Options": {
        "points": 15,
        "description": "Prevents Clickjacking attacks",
        "severity": "high",
    },
    "X-Content-Type-Options": {
        "points": 10,
        "description": "Stops MIME-type sniffing",
        "severity": "medium",
    },
    "Referrer-Policy": {
        "points": 10,
        "description": "Controls how much referrer info is shared",
        "severity": "medium",
    },
    "Permissions-Policy": {
        "points": 10,
        "description": "Restricts browser features (camera, mic, etc.)",
        "severity": "medium",
    },
}


def analyze_headers(headers: dict) -> dict:
    """Analyze HTTP response headers for security posture."""
    # Normalize headers to lowercase for comparison
    normalized = {k.lower(): v for k, v in headers.items()}

    results = {}
    total_points = 0
    max_points = sum(h["points"] for h in SECURITY_HEADERS.values())

    for header, meta in SECURITY_HEADERS.items():
        key = header.lower()
        present = key in normalized
        value = normalized.get(key, None)
        results[header] = {
            "present": present,
            "value": value,
            "points": meta["points"] if present else 0,
            "description": meta["description"],
            "severity": meta["severity"],
        }
        if present:
            total_points += meta["points"]

    return {
        "headers": results,
        "score": total_points,
        "max_score": max_points,
        "raw_headers": {
            k: v
            for k, v in headers.items()
            if k.lower()
            not in [
                "connection",
                "transfer-encoding",
                "keep-alive",
            ]
        },
    }
