import re
from urllib.parse import urlparse

# Define suspicious keywords
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "update", "free", "bonus", "verify", "bank",
    "account", "signin", "signup", "webscr", "ebayisapi", "confirm",
    "submit", "admin", "wp", "wordpress", "pay", "payment", "invoice",
    "billing", "password", "reset", "unlock", "alert", "security",
    "support", "helpdesk", "service", "apple", "paypal", "amazon",
    "google", "microsoft", "outlook", "office365", "dropbox", "drive",
    "cloud", "wallet", "crypto", "bitcoin", "gift", "prize", "winner",
    "claim", "urgent", "important", "notice", "update", "verify", "validate"
]

# Whitelist of trusted domains (add more as needed)
WHITELISTED_DOMAINS = [
    "google.com", "amazon.com", "microsoft.com", "paypal.com", "apple.com",
    "outlook.com", "office.com", "dropbox.com", "drive.google.com"
]

def is_whitelisted(url):
    hostname = urlparse(url).hostname or ""
    for domain in WHITELISTED_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False

def check_url_rules(url):
    score = 0
    reasons = []

    # Whitelist check
    if is_whitelisted(url):
        reasons.append("Domain is whitelisted (trusted)")
        return {
            "rule_score": 0,
            "reasons": reasons
        }

    # Rule 1: URL length is too long
    if len(url) > 75:
        score += 0.5  # Lowered penalty
        reasons.append("URL is unusually long")

    # Rule 2: Check for presence of IP address
    if re.match(r"http[s]?://\d{1,3}(\.\d{1,3}){3}", url):
        score += 2
        reasons.append("URL uses IP address instead of domain")

    # Rule 3: Suspicious keywords
    keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if keyword_hits:
        score += 0.5 * len(keyword_hits)  # 0.5 per keyword
        reasons.append(f"Contains suspicious keywords: {', '.join(set(keyword_hits))}")

    # Rule 4: Excessive subdomains
    hostname = urlparse(url).hostname or ""
    if hostname.count('.') > 3:
        score += 1
        reasons.append("Too many subdomains")

    # Rule 5: URL uses HTTPS (bonus: reduce score if safe)
    if url.startswith("https://"):
        score -= 1
        reasons.append("Uses HTTPS (good sign)")

    # Ensure score is not negative
    score = max(score, 0)

    # Final rule-based result
    return {
        "rule_score": score,
        "reasons": reasons
    }