def check_clickjacking(headers: dict) -> dict:
    """
    Evaluate clickjacking protection based on response headers.
    Returns status: SAFE | LIKELY_VULNERABLE | PARTIAL
    """
    normalized = {k.lower(): v for k, v in headers.items()}

    xfo = normalized.get("x-frame-options", "").strip().upper()
    csp = normalized.get("content-security-policy", "").lower()

    has_xfo_protection = xfo in ("DENY", "SAMEORIGIN")
    has_csp_frame_ancestors = "frame-ancestors" in csp

    details = []
    if has_xfo_protection:
        details.append(f"X-Frame-Options: {xfo} ✅")
    else:
        if xfo:
            details.append(f"X-Frame-Options: {xfo} (weak) ⚠️")
        else:
            details.append("X-Frame-Options: Not set ❌")

    if has_csp_frame_ancestors:
        # Extract the frame-ancestors value
        for directive in csp.split(";"):
            if "frame-ancestors" in directive:
                details.append(f"CSP frame-ancestors: {directive.strip()} ✅")
                break
    else:
        details.append("CSP frame-ancestors: Not set ❌")

    if has_xfo_protection or has_csp_frame_ancestors:
        if has_xfo_protection and has_csp_frame_ancestors:
            status = "SAFE"
            label = "Protected"
            color = "green"
        else:
            status = "PARTIAL"
            label = "Partially Protected"
            color = "yellow"
    else:
        status = "LIKELY_VULNERABLE"
        label = "Vulnerable"
        color = "red"

    return {
        "status": status,
        "label": label,
        "color": color,
        "details": details,
        "xfo": xfo or "Not set",
        "csp_frame_ancestors": has_csp_frame_ancestors,
    }
