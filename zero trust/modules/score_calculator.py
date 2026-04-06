def calculate_score(ssl_result: dict, headers_result: dict, tracker_result: dict, clickjack_result: dict) -> dict:
    """
    Calculate a weighted Privacy Score from 0 to 100.

    Breakdown:
    - HTTPS + valid cert  : up to 20 pts
    - Security headers    : up to 80 pts
    - Tracker penalty     : -5 pts per tracker (min 0)
    """
    score = 0
    breakdown = []

    # --- HTTPS & SSL (20 pts) ---
    ssl_score = 0
    if ssl_result.get("uses_https"):
        ssl_score += 10
        if ssl_result.get("cert_valid"):
            ssl_score += 10
            days = ssl_result.get("days_until_expiry")
            if days is not None and days < 30:
                ssl_score -= 5  # expiring soon penalty
    score += ssl_score
    breakdown.append({
        "category": "HTTPS & SSL",
        "score": ssl_score,
        "max": 20,
        "note": (
            "Valid HTTPS with good certificate"
            if ssl_score == 20 else
            "HTTPS present but certificate issue" if ssl_score > 0 else
            "No HTTPS — plain HTTP connection"
        ),
    })

    # --- Security Headers (up to 80 pts) ---
    header_score = headers_result.get("score", 0)
    score += header_score
    breakdown.append({
        "category": "Security Headers",
        "score": header_score,
        "max": headers_result.get("max_score", 80),
        "note": f"{sum(1 for h in headers_result['headers'].values() if h['present'])} of {len(headers_result['headers'])} recommended headers present",
    })

    # --- Tracker Penalty ---
    tracker_count = tracker_result.get("tracker_count", 0)
    penalty = min(tracker_count * 5, score)  # can't go below 0
    score -= penalty
    breakdown.append({
        "category": "Tracker Penalty",
        "score": -penalty,
        "max": 0,
        "note": f"{tracker_count} tracker(s) found — −5 pts each",
    })

    final_score = max(0, min(100, score))

    # Grade
    if final_score >= 80:
        grade, grade_color = "A", "#22c55e"
    elif final_score >= 60:
        grade, grade_color = "B", "#84cc16"
    elif final_score >= 40:
        grade, grade_color = "C", "#eab308"
    elif final_score >= 20:
        grade, grade_color = "D", "#f97316"
    else:
        grade, grade_color = "F", "#ef4444"

    return {
        "score": final_score,
        "grade": grade,
        "grade_color": grade_color,
        "breakdown": breakdown,
    }
