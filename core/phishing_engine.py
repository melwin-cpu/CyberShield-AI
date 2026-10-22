
import ipaddress
from urllib.parse import urlparse


FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "dot_count",
    "slash_count",
    "hyphen_count",
    "underscore_count",
    "at_count",
    "question_count",
    "equal_count",
    "ampersand_count",
    "percent_count",
    "digit_count",
    "letter_count",
    "subdomain_count",
    "uses_https",
    "uses_ip",
    "has_port",
    "has_punycode",
    "has_fragment",
    "has_query",
    "has_login_keyword",
    "has_verify_keyword",
    "has_account_keyword",
    "has_security_keyword",
    "has_password_keyword",
    "has_bank_keyword",
]


def normalize_url(url):
    """Validate a URL and normalize an empty root path."""

    if not isinstance(url, str):
        raise TypeError("URL must be a string.")

    url = url.strip()

    if not url:
        raise ValueError("URL cannot be empty.")

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError("URL hostname is missing or invalid.")

    # Treat an empty root path and a single trailing root slash alike.
    # Preserve query strings and fragments.
    if parsed.path == "/":
        url = parsed._replace(path="").geturl()
        parsed = urlparse(url)

    return url, parsed


def extract_url_features(url):
    """Extract 27 numerical features in a fixed order."""

    test_url, parsed = normalize_url(url)

    domain = (parsed.hostname or "").lower().rstrip(".")

    if not domain:
        raise ValueError("URL hostname is missing.")

    domain_parts = [part for part in domain.split(".") if part]
    subdomain_count = max(0, len(domain_parts) - 2)

    try:
        ipaddress.ip_address(domain)
        uses_ip = 1
    except ValueError:
        uses_ip = 0

    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 0

    lower_url = test_url.lower()
    path = parsed.path or ""

    features = {
        "url_length": len(test_url),
        "domain_length": len(domain),
        "path_length": len(path),
        "dot_count": test_url.count("."),
        "slash_count": path.count("/"),
        "hyphen_count": test_url.count("-"),
        "underscore_count": test_url.count("_"),
        "at_count": test_url.count("@"),
        "question_count": test_url.count("?"),
        "equal_count": test_url.count("="),
        "ampersand_count": test_url.count("&"),
        "percent_count": test_url.count("%"),
        "digit_count": sum(char.isdigit() for char in test_url),
        "letter_count": sum(char.isalpha() for char in test_url),
        "subdomain_count": subdomain_count,
        "uses_https": int(parsed.scheme.lower() == "https"),
        "uses_ip": uses_ip,
        "has_port": has_port,
        "has_punycode": int("xn--" in domain),
        "has_fragment": int(bool(parsed.fragment)),
        "has_query": int(bool(parsed.query)),
        "has_login_keyword": int("login" in lower_url),
        "has_verify_keyword": int("verify" in lower_url),
        "has_account_keyword": int("account" in lower_url),
        "has_security_keyword": int("security" in lower_url),
        "has_password_keyword": int("password" in lower_url),
        "has_bank_keyword": int("bank" in lower_url),
    }

    if len(features) != len(FEATURE_NAMES):
        raise RuntimeError("Feature count does not match FEATURE_NAMES.")

    return features


def get_feature_vector(url):
    """Return features in the documented order."""

    features = extract_url_features(url)
    return [features[name] for name in FEATURE_NAMES]


def calculate_url_risk(features):
    """Return a heuristic score from 0 to 100, not an ML prediction."""

    risk = 0

    if features["url_length"] > 75:
        risk += 10

    if features["url_length"] > 120:
        risk += 10

    if features["uses_ip"]:
        risk += 20

    if not features["uses_https"]:
        risk += 10

    if features["subdomain_count"] > 2:
        risk += 10

    if features["at_count"] > 0:
        risk += 15

    if features["has_punycode"]:
        risk += 15

    suspicious_keywords = sum(
        features[name]
        for name in (
            "has_login_keyword",
            "has_verify_keyword",
            "has_account_keyword",
            "has_security_keyword",
            "has_password_keyword",
            "has_bank_keyword",
        )
    )

    risk += min(suspicious_keywords * 5, 20)

    return min(risk, 100)
