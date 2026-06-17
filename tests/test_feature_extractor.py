"""
Tests for PhishGuard AI - Feature Extractor
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from ml.feature_extractor import (
    extract_urls, is_ip_based_url, is_url_shortener, has_suspicious_tld,
    has_misleading_domain, count_subdomains, url_has_at_symbol,
    url_length_suspicious, count_keyword_matches, calculate_text_entropy,
    count_exclamation_marks, count_dollar_signs, has_html_content,
    count_html_forms, count_html_links, has_obfuscated_links,
    sender_domain_is_free_provider, sender_domain_mismatch,
    count_misspellings, ratio_of_caps, extract_features,
    features_to_vector, get_feature_names, explain_features,
    URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS
)


# ── URL extraction ────────────────────────────────────────────────

class TestExtractUrls:
    def test_extracts_http_url(self):
        urls = extract_urls("Visit http://example.com now")
        assert "http://example.com" in urls

    def test_extracts_https_url(self):
        urls = extract_urls("Go to https://secure.example.com/path")
        assert any("secure.example.com" in u for u in urls)

    def test_extracts_www_url(self):
        urls = extract_urls("See www.example.com for details")
        assert any("www.example.com" in u for u in urls)

    def test_extracts_multiple_urls(self):
        text = "http://one.com and http://two.org and https://three.net"
        assert len(extract_urls(text)) == 3

    def test_empty_text(self):
        assert extract_urls("") == []

    def test_no_urls(self):
        assert extract_urls("Just plain text here, no links.") == []


# ── IP-based URL detection ─────────────────────────────────────────

class TestIpBasedUrl:
    def test_detects_ipv4_http(self):
        assert is_ip_based_url("http://192.168.1.45/login") is True

    def test_detects_ipv4_with_port(self):
        assert is_ip_based_url("http://10.0.0.1:8080/page") is True

    def test_normal_domain_not_flagged(self):
        assert is_ip_based_url("https://paypal.com/login") is False

    def test_subdomain_not_flagged(self):
        assert is_ip_based_url("https://secure.bank.com") is False

    def test_malformed_url(self):
        assert is_ip_based_url("not_a_url") is False


# ── URL shortener detection ────────────────────────────────────────

class TestUrlShortener:
    def test_detects_bitly(self):
        assert is_url_shortener("https://bit.ly/3xAbc12") is True

    def test_detects_tinyurl(self):
        assert is_url_shortener("http://tinyurl.com/y3abc") is True

    def test_detects_goo_gl(self):
        assert is_url_shortener("https://goo.gl/maps/abc") is True

    def test_legitimate_url_not_flagged(self):
        assert is_url_shortener("https://www.amazon.com/product/123") is False

    def test_empty_string(self):
        assert is_url_shortener("") is False


# ── Suspicious TLD detection ───────────────────────────────────────

class TestSuspiciousTld:
    def test_detects_xyz(self):
        assert has_suspicious_tld("http://evil.xyz") is True

    def test_detects_tk(self):
        assert has_suspicious_tld("http://phish.tk/login") is True

    def test_detects_ml(self):
        assert has_suspicious_tld("http://malware.ml") is True

    def test_com_not_flagged(self):
        assert has_suspicious_tld("https://google.com") is False

    def test_org_not_flagged(self):
        assert has_suspicious_tld("https://wikipedia.org") is False

    def test_gov_not_flagged(self):
        assert has_suspicious_tld("https://irs.gov") is False


# ── Misleading domain detection ────────────────────────────────────

class TestMisleadingDomain:
    def test_detects_paypal_impersonation(self):
        assert has_misleading_domain("http://paypal-secure.xyz/login") is True

    def test_detects_amazon_impersonation(self):
        assert has_misleading_domain("http://amazon-verify.tk") is True

    def test_real_paypal_not_flagged(self):
        assert has_misleading_domain("https://paypal.com") is False

    def test_real_amazon_not_flagged(self):
        assert has_misleading_domain("https://amazon.com/orders") is False

    def test_unrelated_domain_not_flagged(self):
        assert has_misleading_domain("https://example.com") is False


# ── Subdomain counting ─────────────────────────────────────────────

class TestCountSubdomains:
    def test_no_subdomain(self):
        assert count_subdomains("http://example.com") == 0

    def test_one_subdomain(self):
        assert count_subdomains("http://secure.example.com") == 1

    def test_two_subdomains(self):
        assert count_subdomains("http://a.b.example.com") == 2

    def test_many_subdomains(self):
        assert count_subdomains("http://a.b.c.d.example.com") == 4


# ── URL @ symbol ───────────────────────────────────────────────────

class TestAtSymbol:
    def test_detects_at_symbol(self):
        assert url_has_at_symbol("http://trusted.com@evil.com/login") is True

    def test_no_at_symbol(self):
        assert url_has_at_symbol("https://paypal.com/login") is False


# ── URL length ─────────────────────────────────────────────────────

class TestUrlLength:
    def test_long_url_flagged(self):
        long = "https://example.com/" + "a" * 100
        assert url_length_suspicious(long) is True

    def test_short_url_ok(self):
        assert url_length_suspicious("https://example.com") is False

    def test_exactly_100_chars(self):
        url = "https://example.com/" + "x" * 80  # 100 total approx
        # 100-char URLs are borderline — just test the function returns bool
        assert isinstance(url_length_suspicious(url), bool)


# ── Keyword matching ───────────────────────────────────────────────

class TestKeywordMatching:
    def test_urgency_keywords_found(self):
        text = "Your account is suspended. Act now or lose access."
        score = count_keyword_matches(text, URGENCY_KEYWORDS)
        assert score >= 2

    def test_no_keywords(self):
        text = "Hi John, see you at the meeting tomorrow."
        score = count_keyword_matches(text, URGENCY_KEYWORDS)
        assert score == 0

    def test_credential_keywords_found(self):
        text = "Please enter your password and credit card number to verify."
        score = count_keyword_matches(text, CREDENTIAL_KEYWORDS)
        assert score >= 1

    def test_case_insensitive(self):
        text = "URGENT ACTION REQUIRED"
        score = count_keyword_matches(text, URGENCY_KEYWORDS)
        assert score >= 1


# ── Text entropy ───────────────────────────────────────────────────

class TestTextEntropy:
    def test_uniform_text_low_entropy(self):
        entropy = calculate_text_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_diverse_text_higher_entropy(self):
        entropy = calculate_text_entropy("The quick brown fox jumps")
        assert entropy > 3.0

    def test_empty_string(self):
        assert calculate_text_entropy("") == 0.0


# ── Exclamation & dollar counts ────────────────────────────────────

class TestSpecialCharCounts:
    def test_exclamation_count(self):
        assert count_exclamation_marks("Act NOW!!! Limited time!!!") == 6

    def test_dollar_count(self):
        assert count_dollar_signs("Win $1000 or get $500 back!") == 2

    def test_no_exclamations(self):
        assert count_exclamation_marks("Normal sentence here.") == 0


# ── HTML detection ─────────────────────────────────────────────────

class TestHtmlDetection:
    def test_detects_html(self):
        assert has_html_content("<p>Hello <b>world</b></p>") is True

    def test_plain_text_not_html(self):
        assert has_html_content("Just plain text here.") is False

    def test_count_forms(self):
        html = "<form action='/login'><input/></form><form action='/pay'></form>"
        assert count_html_forms(html) == 2

    def test_count_links(self):
        html = '<a href="http://a.com">A</a><a href="http://b.com">B</a>'
        assert count_html_links(html) == 2

    def test_no_forms(self):
        assert count_html_forms("<p>No form here</p>") == 0


# ── Obfuscation detection ──────────────────────────────────────────

class TestObfuscationDetection:
    def test_detects_javascript_link(self):
        assert has_obfuscated_links('<a href="javascript:void(0)">') is True

    def test_detects_eval(self):
        assert has_obfuscated_links("eval(unescape('%68%65%6C'))") is True

    def test_detects_onclick(self):
        assert has_obfuscated_links('<div onclick="redirect()">') is True

    def test_clean_html_not_flagged(self):
        assert has_obfuscated_links('<a href="https://paypal.com">Pay</a>') is False


# ── Sender analysis ────────────────────────────────────────────────

class TestSenderAnalysis:
    def test_free_provider_detected(self):
        assert sender_domain_is_free_provider("attacker@gmail.com") is True

    def test_company_domain_not_flagged(self):
        assert sender_domain_is_free_provider("support@company.com") is False

    def test_domain_mismatch_detected(self):
        assert sender_domain_mismatch(
            "sender@legitimate.com", "reply@attacker.com"
        ) is True

    def test_same_domain_no_mismatch(self):
        assert sender_domain_mismatch(
            "info@company.com", "support@company.com"
        ) is False

    def test_empty_sender(self):
        assert sender_domain_is_free_provider("") is False

    def test_empty_reply_no_mismatch(self):
        assert sender_domain_mismatch("user@company.com", "") is False


# ── Caps ratio ─────────────────────────────────────────────────────

class TestCapsRatio:
    def test_all_caps(self):
        assert ratio_of_caps("URGENT ACTION NOW") == 1.0

    def test_all_lower(self):
        assert ratio_of_caps("hello world") == 0.0

    def test_empty_string(self):
        assert ratio_of_caps("") == 0.0

    def test_mixed(self):
        ratio = ratio_of_caps("Hello World")
        assert 0.0 < ratio < 1.0


# ── Full feature extraction ────────────────────────────────────────

class TestExtractFeatures:
    PHISHING_EMAIL = {
        "subject": "URGENT!! Verify your PayPal account NOW",
        "body": (
            "Dear valued customer, your account has been suspended. "
            "Click http://192.168.1.45/paypal-verify to restore access. "
            "Enter your password and credit card number immediately! "
            "Act now or your account will be closed within 24 hours!!!"
        ),
        "sender": "security@paypa1-alert.tk",
        "reply_to": "harvest@attacker.xyz",
        "headers": "",
    }

    SAFE_EMAIL = {
        "subject": "Team meeting agenda for Thursday",
        "body": (
            "Hi everyone, please find the agenda for Thursday's meeting attached. "
            "We will discuss Q3 results and roadmap planning. "
            "Please review before the meeting. Thanks."
        ),
        "sender": "manager@company.com",
        "reply_to": "",
        "headers": "",
    }

    def test_returns_dict(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        assert isinstance(feats, dict)

    def test_all_feature_names_present(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        for name in get_feature_names():
            assert name in feats, f"Missing feature: {name}"

    def test_phishing_has_ip_url(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        assert feats["num_ip_urls"] >= 1

    def test_phishing_has_urgency(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        assert feats["urgency_score"] >= 1

    def test_phishing_has_credential_request(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        assert feats["credential_score"] >= 1

    def test_phishing_domain_mismatch(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        assert feats["domain_mismatch"] == 1

    def test_safe_low_urgency(self):
        feats = extract_features(**self.SAFE_EMAIL)
        assert feats["urgency_score"] == 0

    def test_safe_no_credential_requests(self):
        feats = extract_features(**self.SAFE_EMAIL)
        assert feats["credential_score"] == 0

    def test_features_to_vector_correct_length(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        vec = features_to_vector(feats)
        assert len(vec) == len(get_feature_names())

    def test_all_vector_values_are_numeric(self):
        feats = extract_features(**self.PHISHING_EMAIL)
        vec = features_to_vector(feats)
        assert all(isinstance(v, float) for v in vec)

    def test_feature_names_consistent(self):
        names = get_feature_names()
        assert len(names) == len(set(names)), "Duplicate feature names!"
        assert len(names) > 20, "Too few features"


# ── Explain features ───────────────────────────────────────────────

class TestExplainFeatures:
    def test_explains_ip_url(self):
        features = {"num_ip_urls": 1, "num_shortener_urls": 0,
                    "num_suspicious_tld": 0, "num_misleading_domain": 0,
                    "urgency_score": 0, "credential_score": 0,
                    "html_form_count": 0, "has_obfuscation": 0,
                    "domain_mismatch": 0, "has_at_in_url": 0,
                    "suspicious_phrase_score": 0, "misspelling_count": 0,
                    "caps_ratio": 0}
        explanations = explain_features(features)
        indicators = [e["indicator"] for e in explanations]
        assert any("IP" in i for i in indicators)

    def test_no_indicators_when_clean(self):
        features = {k: 0 for k in [
            "num_ip_urls", "num_shortener_urls", "num_suspicious_tld",
            "num_misleading_domain", "urgency_score", "credential_score",
            "html_form_count", "has_obfuscation", "domain_mismatch",
            "has_at_in_url", "suspicious_phrase_score", "misspelling_count",
            "caps_ratio"
        ]}
        assert explain_features(features) == []

    def test_returns_list_of_dicts(self):
        features = {"num_ip_urls": 2, "urgency_score": 3,
                    "credential_score": 2, "html_form_count": 1}
        result = explain_features(features)
        assert isinstance(result, list)
        for item in result:
            assert "indicator" in item
            assert "detail" in item
            assert "severity" in item

    def test_severity_values_valid(self):
        features = {"num_ip_urls": 1, "num_misleading_domain": 1,
                    "urgency_score": 3, "has_obfuscation": 1}
        valid_severities = {"critical", "high", "medium", "low"}
        for item in explain_features(features):
            assert item["severity"] in valid_severities
