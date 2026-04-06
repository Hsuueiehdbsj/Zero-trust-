import ssl
import socket
from datetime import datetime


def check_ssl(url: str) -> dict:
    """Check SSL/TLS status for a given URL."""
    result = {
        "uses_https": False,
        "cert_valid": False,
        "cert_issuer": "N/A",
        "cert_expiry": "N/A",
        "days_until_expiry": None,
        "error": None,
    }

    if url.startswith("https://"):
        result["uses_https"] = True
        hostname = url.replace("https://", "").split("/")[0].split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=10),
                server_hostname=hostname,
            ) as ssock:
                cert = ssock.getpeercert()
                # Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                result["cert_issuer"] = issuer_dict.get(
                    "organizationName", issuer_dict.get("commonName", "Unknown")
                )
                # Expiry
                expiry_str = cert.get("notAfter", "")
                if expiry_str:
                    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    result["cert_expiry"] = expiry_date.strftime("%d %b %Y")
                    result["days_until_expiry"] = (expiry_date - datetime.utcnow()).days
                result["cert_valid"] = True
        except ssl.SSLCertVerificationError as e:
            result["cert_valid"] = False
            result["error"] = f"Certificate error: {str(e)}"
        except Exception as e:
            result["error"] = f"Could not connect: {str(e)}"
    else:
        result["uses_https"] = False

    return result
