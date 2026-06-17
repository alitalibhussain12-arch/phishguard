"""
PhishGuard AI - Feature Extractor
Extracts features from email content for phishing detection.
"""

import re
import math
import logging
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Any

logger = logging.getLogger(__name__)

# ── Keyword Lists ──────────────────────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "limited time", "expires",
    "deadline", "last chance", "final notice", "time sensitive",
    "respond now", "don't delay", "within 24 hours", "within 48 hours",
    "account suspended", "account locked", "immediate action", "right away",
    "as soon as possible", "asap", "critical", "alert", "warning",
    "important notice", "your account will be", "verify now"
]

CREDENTIAL_KEYWORDS = [
    "enter your password", "confirm your password", "verify your identity",
    "update your information", "confirm your account", "validate your account",
    "provide your credentials", "submit your details", "log in to verify",
    "sign in to confirm", "click here to verify", "click here to confirm",
    "enter your credit card", "provide your ssn", "social security",
    "bank account number", "update payment", "billing information",
    "username and password", "user id and password", "login details",
    "reset your password", "your password has expired", "verify email"
]

SUSPICIOUS_PHRASES = [
    "you have been selected", "congratulations you won", "you are a winner",
    "claim your prize", "free gift", "no cost", "100% free", "risk free",
    "guaranteed", "you've been chosen", "special offer", "exclusive deal",
    "act immediately", "do not ignore", "failure to respond",
    "your account has been compromised", "unauthorized access detected",
    "suspicious activity", "we noticed unusual", "confirm your information",
    "dear customer", "dear user", "dear account holder", "dear valued member",
    "click below", "click the link", "follow the link"
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd", "tiny.cc",
    "lnkd.in", "ift.tt", "dlvr.it", "soo.gd", "cli.re", "ity.im",
    "q.gs", "viralurl.com", "bc.vc", "adf.ly", "shrinkonce.com"
]

LEGITIMATE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".work",
    ".click", ".link", ".download", ".stream", ".gdn", ".racing",
    ".win", ".bid", ".loan", ".party", ".trade", ".webcam"
}

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "inbox.com"
}


# ── URL Analysis ───────────────────────────────────────────────────────────────

def extract_urls(text: str) -> List[str]:
    """Extract all URLs from email text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]\']+|'
        r'www\.[^\s<>"{}|\\^`\[\]\']+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def is_ip_based_url(url: str) -> bool:
    """Check if URL uses an IP address instead of a domain name."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
        ipv4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        return bool(ipv4.match(host))
    except Exception:
        return False


def is_url_shortener(url: str) -> bool:
    """Check if URL uses a known URL shortener service."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        return any(shortener in domain for shortener in URL_SHORTENERS)
    except Exception:
        return False


def has_suspicious_tld(url: str) -> bool:
    """Check if URL has a suspicious top-level domain."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True
        return False
    except Exception:
        return False


def has_misleading_domain(url: str) -> bool:
    """
    Detect domains trying to mimic legitimate brands.
    E.g. paypal-secure.com, amazon-login.net
    """
    trusted_brands = [
        "paypal", "amazon", "google", "microsoft", "apple", "netflix",
        "facebook", "instagram", "twitter", "bank", "chase", "wellsfargo",
        "citibank", "usps", "fedex", "ups", "dhl", "irs", "ebay"
    ]
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        domain_base = domain.split(".")[0]
        for brand in trusted_brands:
            if brand in domain_base and domain_base != brand:
                return True
        return False
    except Exception:
        return False


def count_subdomains(url: str) -> int:
    """Count the number of subdomains in a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0]
        parts = host.split(".")
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def url_has_at_symbol(url: str) -> bool:
    """Check if URL contains @ symbol (used to hide real destination)."""
    return "@" in url


def url_length_suspicious(url: str) -> bool:
    """Flag URLs that are excessively long (> 100 chars)."""
    return len(url) > 100


# ── Text Analysis ──────────────────────────────────────────────────────────────

def count_keyword_matches(text: str, keywords: List[str]) -> int:
    """Count how many keywords from a list appear in the text."""
    text_lower = text.lower()
    return sum(1 for kw in keywords if kw in text_lower)


def calculate_text_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.
    High entropy may indicate encoded/obfuscated content.
    """
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
    return round(entropy, 4)


def count_exclamation_marks(text: str) -> int:
    """Count exclamation marks — common in spam/phishing."""
    return text.count("!")


def count_dollar_signs(text: str) -> int:
    """Count dollar signs — common in financial phishing."""
    return text.count("$")


def has_html_content(text: str) -> bool:
    """Detect if email contains HTML tags."""
    return bool(re.search(r'<[a-zA-Z][^>]*>', text))


def count_html_forms(text: str) -> int:
    """Count <form> elements in HTML email content."""
    return len(re.findall(r'<form', text, re.IGNORECASE))


def count_html_links(text: str) -> int:
    """Count <a href> links in HTML email content."""
    return len(re.findall(r'<a\s+[^>]*href', text, re.IGNORECASE))


def has_obfuscated_links(text: str) -> bool:
    """Detect JavaScript-based or obfuscated redirect links."""
    patterns = [
        r'javascript\s*:',
        r'onclick\s*=',
        r'document\.location',
        r'window\.location',
        r'document\.write\s*\(',
        r'eval\s*\(',
        r'unescape\s*\('
    ]
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def sender_domain_is_free_provider(sender: str) -> bool:
    """Check if sender uses a free email provider."""
    if not sender:
        return False
    match = re.search(r'@([\w.-]+)', sender.lower())
    if match:
        domain = match.group(1)
        return domain in FREE_EMAIL_PROVIDERS
    return False


def sender_domain_mismatch(sender: str, reply_to: str) -> bool:
    """Check if sender domain differs from reply-to domain."""
    if not sender or not reply_to:
        return False

    def extract_domain(addr: str) -> str:
        match = re.search(r'@([\w.-]+)', addr.lower())
        return match.group(1) if match else ""

    sender_domain = extract_domain(sender)
    reply_domain = extract_domain(reply_to)
    return bool(sender_domain and reply_domain and sender_domain != reply_domain)


def count_misspellings(text: str) -> int:
    """
    Heuristic misspelling detector based on common phishing substitutions.
    Not a full spell-checker — catches deliberate obfuscations.
    """
    patterns = [
        r'\bpaypa1\b', r'\bgoog1e\b', r'\bmicros0ft\b', r'\bamazon\b',
        r'\bverif[yi]cation\b', r'\baccaunt\b', r'\bpasswrod\b',
        r'\breciept\b', r'\bconfirn\b', r'\bsuspious\b'
    ]
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE))


def text_word_count(text: str) -> int:
    """Count number of words in text."""
    return len(text.split())


def ratio_of_caps(text: str) -> float:
    """Calculate ratio of uppercase letters to total letters."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    caps = sum(1 for c in letters if c.isupper())
    return round(caps / len(letters), 4)


# ── Master Feature Extraction ──────────────────────────────────────────────────

def extract_features(
    subject: str = "",
    body: str = "",
    sender: str = "",
    reply_to: str = "",
    headers: str = ""
) -> Dict[str, Any]:
    """
    Extract all phishing-detection features from an email.

    Args:
        subject:   Email subject line
        body:      Full email body text
        sender:    From address
        reply_to:  Reply-To address
        headers:   Raw email headers

    Returns:
        Dictionary of feature_name → numeric value (all ints/floats)
    """
    full_text = f"{subject} {body} {headers}"
    urls = extract_urls(full_text)

    # ── URL features ────────────────────────────────────────────────────────
    num_urls = len(urls)
    num_ip_urls = sum(1 for u in urls if is_ip_based_url(u))
    num_shortener_urls = sum(1 for u in urls if is_url_shortener(u))
    num_suspicious_tld = sum(1 for u in urls if has_suspicious_tld(u))
    num_misleading_domain = sum(1 for u in urls if has_misleading_domain(u))
    max_subdomains = max((count_subdomains(u) for u in urls), default=0)
    has_at_in_url = int(any(url_has_at_symbol(u) for u in urls))
    has_long_url = int(any(url_length_suspicious(u) for u in urls))

    # ── Keyword features ─────────────────────────────────────────────────────
    urgency_score = count_keyword_matches(full_text, URGENCY_KEYWORDS)
    credential_score = count_keyword_matches(full_text, CREDENTIAL_KEYWORDS)
    suspicious_phrase_score = count_keyword_matches(full_text, SUSPICIOUS_PHRASES)

    # ── Text features ────────────────────────────────────────────────────────
    body_entropy = calculate_text_entropy(body[:500])  # sample first 500 chars
    exclamation_count = count_exclamation_marks(full_text)
    dollar_count = count_dollar_signs(full_text)
    html_present = int(has_html_content(body))
    html_form_count = count_html_forms(body)
    html_link_count = count_html_links(body)
    has_obfuscation = int(has_obfuscated_links(body))
    misspelling_count = count_misspellings(full_text)
    word_count = text_word_count(body)
    caps_ratio = ratio_of_caps(body)
    subject_caps_ratio = ratio_of_caps(subject)
    subject_length = len(subject)
    body_length = len(body)

    # ── Sender / header features ─────────────────────────────────────────────
    free_provider = int(sender_domain_is_free_provider(sender))
    domain_mismatch = int(sender_domain_mismatch(sender, reply_to))
    has_reply_to = int(bool(reply_to))

    # ── Subject features ─────────────────────────────────────────────────────
    subject_urgency = count_keyword_matches(subject, URGENCY_KEYWORDS)
    subject_exclamation = count_exclamation_marks(subject)

    features = {
        # URL
        "num_urls": num_urls,
        "num_ip_urls": num_ip_urls,
        "num_shortener_urls": num_shortener_urls,
        "num_suspicious_tld": num_suspicious_tld,
        "num_misleading_domain": num_misleading_domain,
        "max_subdomains": max_subdomains,
        "has_at_in_url": has_at_in_url,
        "has_long_url": has_long_url,
        # Keywords
        "urgency_score": urgency_score,
        "credential_score": credential_score,
        "suspicious_phrase_score": suspicious_phrase_score,
        # Text
        "body_entropy": body_entropy,
        "exclamation_count": exclamation_count,
        "dollar_count": dollar_count,
        "html_present": html_present,
        "html_form_count": html_form_count,
        "html_link_count": html_link_count,
        "has_obfuscation": has_obfuscation,
        "misspelling_count": misspelling_count,
        "word_count": word_count,
        "caps_ratio": caps_ratio,
        "subject_caps_ratio": subject_caps_ratio,
        "subject_length": subject_length,
        "body_length": body_length,
        # Sender/headers
        "free_provider": free_provider,
        "domain_mismatch": domain_mismatch,
        "has_reply_to": has_reply_to,
        # Subject
        "subject_urgency": subject_urgency,
        "subject_exclamation": subject_exclamation,
    }

    return features


def features_to_vector(features: Dict[str, Any]) -> List[float]:
    """
    Convert feature dict to ordered numeric vector for ML models.
    Order must stay consistent with training.
    """
    ordered_keys = [
        "num_urls", "num_ip_urls", "num_shortener_urls", "num_suspicious_tld",
        "num_misleading_domain", "max_subdomains", "has_at_in_url", "has_long_url",
        "urgency_score", "credential_score", "suspicious_phrase_score",
        "body_entropy", "exclamation_count", "dollar_count",
        "html_present", "html_form_count", "html_link_count", "has_obfuscation",
        "misspelling_count", "word_count", "caps_ratio", "subject_caps_ratio",
        "subject_length", "body_length", "free_provider", "domain_mismatch",
        "has_reply_to", "subject_urgency", "subject_exclamation"
    ]
    return [float(features.get(k, 0)) for k in ordered_keys]


def get_feature_names() -> List[str]:
    """Return ordered list of feature names (must match features_to_vector)."""
    return [
        "num_urls", "num_ip_urls", "num_shortener_urls", "num_suspicious_tld",
        "num_misleading_domain", "max_subdomains", "has_at_in_url", "has_long_url",
        "urgency_score", "credential_score", "suspicious_phrase_score",
        "body_entropy", "exclamation_count", "dollar_count",
        "html_present", "html_form_count", "html_link_count", "has_obfuscation",
        "misspelling_count", "word_count", "caps_ratio", "subject_caps_ratio",
        "subject_length", "body_length", "free_provider", "domain_mismatch",
        "has_reply_to", "subject_urgency", "subject_exclamation"
    ]


def explain_features(features: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate human-readable explanations for triggered phishing indicators.

    Returns a list of {"indicator": ..., "detail": ..., "severity": ...} dicts.
    """
    explanations = []

    if features.get("num_ip_urls", 0) > 0:
        explanations.append({
            "indicator": "IP-based URL detected",
            "detail": f"Found {features['num_ip_urls']} URL(s) using raw IP addresses instead of domain names — a classic phishing technique.",
            "severity": "high"
        })

    if features.get("num_shortener_urls", 0) > 0:
        explanations.append({
            "indicator": "URL shortener detected",
            "detail": f"Found {features['num_shortener_urls']} shortened URL(s). Attackers use these to hide malicious destinations.",
            "severity": "medium"
        })

    if features.get("num_suspicious_tld", 0) > 0:
        explanations.append({
            "indicator": "Suspicious domain extension",
            "detail": f"Found {features['num_suspicious_tld']} URL(s) with suspicious TLDs (.xyz, .tk, .ml, etc.) commonly used in phishing campaigns.",
            "severity": "high"
        })

    if features.get("num_misleading_domain", 0) > 0:
        explanations.append({
            "indicator": "Brand impersonation attempt",
            "detail": f"Found {features['num_misleading_domain']} URL(s) that appear to impersonate trusted brands (PayPal, Amazon, Google, etc.).",
            "severity": "critical"
        })

    if features.get("urgency_score", 0) >= 2:
        explanations.append({
            "indicator": "High urgency language",
            "detail": f"Detected {features['urgency_score']} urgency phrases (e.g. 'act now', 'account suspended'). Phishing emails manufacture urgency to bypass critical thinking.",
            "severity": "medium"
        })

    if features.get("credential_score", 0) >= 1:
        explanations.append({
            "indicator": "Credential harvesting language",
            "detail": f"Found {features['credential_score']} phrases requesting login credentials, passwords, or personal information.",
            "severity": "high"
        })

    if features.get("html_form_count", 0) > 0:
        explanations.append({
            "indicator": "Embedded HTML form",
            "detail": f"Email contains {features['html_form_count']} HTML form(s) that may attempt to collect data directly inside the email.",
            "severity": "critical"
        })

    if features.get("has_obfuscation", 0):
        explanations.append({
            "indicator": "Obfuscated/JavaScript links",
            "detail": "Email contains JavaScript-based or obfuscated redirect links designed to hide the true destination.",
            "severity": "critical"
        })

    if features.get("domain_mismatch", 0):
        explanations.append({
            "indicator": "Sender/Reply-To domain mismatch",
            "detail": "The sender address domain differs from the Reply-To address, a common phishing tactic to redirect replies to attackers.",
            "severity": "high"
        })

    if features.get("has_at_in_url", 0):
        explanations.append({
            "indicator": "@ symbol in URL",
            "detail": "URL contains an @ symbol. Browsers ignore everything before @ in a URL, allowing attackers to disguise malicious links.",
            "severity": "high"
        })

    if features.get("suspicious_phrase_score", 0) >= 2:
        explanations.append({
            "indicator": "Suspicious phrases",
            "detail": f"Detected {features['suspicious_phrase_score']} suspicious phrases (e.g. 'you are a winner', 'claim your prize', 'dear customer').",
            "severity": "medium"
        })

    if features.get("misspelling_count", 0) >= 1:
        explanations.append({
            "indicator": "Deliberate misspellings",
            "detail": f"Found {features['misspelling_count']} apparent misspelling(s) — sometimes used to evade spam filters.",
            "severity": "low"
        })

    if features.get("caps_ratio", 0) > 0.3:
        explanations.append({
            "indicator": "Excessive capitalization",
            "detail": f"{int(features['caps_ratio']*100)}% of letters are uppercase — commonly used for false urgency.",
            "severity": "low"
        })

    return explanations
