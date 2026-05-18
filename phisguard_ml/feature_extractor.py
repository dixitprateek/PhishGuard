"""
PhishGuard — Feature Extractor v2
33 features. Fixes false positives on legitimate domains like google.com.

Key additions over v1:
  - Trusted domain whitelist (instant safe exit)
  - Levenshtein distance to top brands (catches typosquatting)
  - Suspicious / reputable TLD flags
  - Domain-only hyphen / digit checks (not whole URL)
  - Consonant ratio (random-looking domains score high)
  - Path depth, domain entropy
"""

import re
import math
import urllib.parse
from dataclasses import dataclass, asdict


# ── Whitelist: always classify these as legit ─────────────────────────────────
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "microsoft.com", "apple.com",
    "amazon.com", "wikipedia.org", "github.com", "reddit.com",
    "stackoverflow.com", "netflix.com", "spotify.com", "twitch.tv",
    "discord.com", "slack.com", "zoom.us", "dropbox.com",
    "paypal.com", "ebay.com", "yahoo.com", "bing.com", "duckduckgo.com",
    "cloudflare.com", "amazonaws.com", "azure.com",
}

# ── Top brands for typosquatting detection ────────────────────────────────────
TOP_BRANDS = [
    "google", "youtube", "facebook", "twitter", "instagram", "linkedin",
    "microsoft", "apple", "amazon", "paypal", "ebay", "netflix", "spotify",
    "github", "wikipedia", "reddit", "yahoo", "outlook", "office365",
    "dropbox", "icloud", "samsung", "adobe", "salesforce",
]

PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "secure", "account",
    "update", "confirm", "banking", "password", "credential",
    "wallet", "support", "helpdesk", "suspended", "unlock",
    "validate", "authenticate", "recovery", "alert", "billing",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "cutt.ly",
    "rebrand.ly", "tiny.cc", "rb.gy",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".club", ".work", ".site", ".online",
    ".buzz", ".pw", ".cc",
}

REPUTABLE_TLDS = {
    ".com", ".org", ".net", ".edu", ".gov", ".io",
    ".co.uk", ".ac.uk", ".ac.in",
}

_IP_RE = re.compile(r"^((\d{1,3}\.){3}\d{1,3})$")


def _levenshtein(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1 != c2)))
        prev = curr
    return prev[-1]


def _min_brand_distance(domain_core: str) -> int:
    return min(_levenshtein(domain_core.lower(), b) for b in TOP_BRANDS)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n)*math.log2(f/n) for f in freq.values())


def _consonant_ratio(s: str) -> float:
    consonants = sum(1 for c in s.lower() if c in "bcdfghjklmnpqrstvwxyz")
    alpha = sum(1 for c in s if c.isalpha())
    return consonants / alpha if alpha else 0.0


def _extract_domain_parts(hostname: str):
    parts = hostname.lower().split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "ac", "com", "org", "net"}:
        tld  = "." + ".".join(parts[-2:])
        core = parts[-3] if len(parts) > 2 else ""
        subs = parts[:-3]
    elif len(parts) >= 2:
        tld  = "." + parts[-1]
        core = parts[-2]
        subs = parts[:-2]
    else:
        tld, core, subs = "", hostname, []
    return subs, core, tld


@dataclass
class URLFeatures:
    # Length
    url_length: int
    domain_length: int
    path_length: int
    query_length: int
    # Counts
    num_dots: int
    num_hyphens_domain: int
    num_underscores: int
    num_slashes: int
    num_digits_domain: int
    num_params: int
    num_subdomains: int
    path_depth: int
    # Booleans
    has_ip_address: int
    has_https: int
    has_www: int
    has_port: int
    has_double_slash: int
    has_at_sign: int
    has_prefix_suffix: int
    has_shortener: int
    has_phish_keyword: int
    has_suspicious_tld: int
    has_reputable_tld: int
    is_trusted_domain: int
    # Continuous
    url_entropy: float
    domain_entropy: float
    consonant_ratio: float
    digit_ratio: float
    special_char_ratio: float
    # Typosquatting
    min_brand_levenshtein: int
    brand_levenshtein_ratio: float
    # Structural
    tld_length: int
    domain_core_length: int

    def to_vector(self) -> list:
        return list(asdict(self).values())

    @staticmethod
    def feature_names() -> list[str]:
        return list(URLFeatures.__dataclass_fields__.keys())


def extract_features(url: str) -> URLFeatures:
    url = url.strip()
    if not re.match(r"https?://", url, re.I):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return URLFeatures(*([0]*29), 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0.0, 0, 0)

    hostname = (parsed.hostname or "").lower()
    path     = parsed.path or ""
    query    = parsed.query or ""
    full_url = url.lower()

    subs, core, tld = _extract_domain_parts(hostname)
    bare = re.sub(r"^www\.", "", hostname)
    is_trusted = int(bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS)

    url_len    = len(url)
    domain_len = len(hostname)
    path_len   = len(path)
    query_len  = len(query)

    num_dots           = hostname.count(".")
    num_hyphens_domain = core.count("-")
    num_underscores    = full_url.count("_")
    num_slashes        = path.count("/")
    num_digits_domain  = sum(c.isdigit() for c in core)
    num_params         = len(urllib.parse.parse_qs(query))
    num_subdomains     = len(subs)
    path_depth         = len([s for s in path.split("/") if s])

    has_ip            = int(bool(_IP_RE.match(hostname)))
    has_https         = int(parsed.scheme.lower() == "https")
    has_www           = int(hostname.startswith("www."))
    has_port          = int(parsed.port is not None)
    has_double_slash  = int("//" in path)
    has_at            = int("@" in full_url)
    has_prefix_suffix = int("-" in core)
    has_shortener     = int(bare in SHORTENERS)
    has_keyword       = int(any(kw in full_url for kw in PHISH_KEYWORDS))
    has_susp_tld      = int(tld in SUSPICIOUS_TLDS)
    has_rep_tld       = int(tld in REPUTABLE_TLDS)

    url_entropy    = _shannon_entropy(hostname)
    domain_entropy = _shannon_entropy(core)
    consonant_rat  = _consonant_ratio(core)

    all_digits    = sum(c.isdigit() for c in full_url)
    digit_ratio   = all_digits / url_len if url_len else 0.0
    special_chars = sum(full_url.count(c) for c in "@-_?=&%#!")
    special_ratio = special_chars / url_len if url_len else 0.0

    min_lev       = _min_brand_distance(core) if core else 99
    avg_brand_len = sum(len(b) for b in TOP_BRANDS) / len(TOP_BRANDS)
    lev_ratio     = min_lev / avg_brand_len

    return URLFeatures(
        url_length=url_len, domain_length=domain_len,
        path_length=path_len, query_length=query_len,
        num_dots=num_dots, num_hyphens_domain=num_hyphens_domain,
        num_underscores=num_underscores, num_slashes=num_slashes,
        num_digits_domain=num_digits_domain, num_params=num_params,
        num_subdomains=num_subdomains, path_depth=path_depth,
        has_ip_address=has_ip, has_https=has_https, has_www=has_www,
        has_port=has_port, has_double_slash=has_double_slash,
        has_at_sign=has_at, has_prefix_suffix=has_prefix_suffix,
        has_shortener=has_shortener, has_phish_keyword=has_keyword,
        has_suspicious_tld=has_susp_tld, has_reputable_tld=has_rep_tld,
        is_trusted_domain=is_trusted,
        url_entropy=url_entropy, domain_entropy=domain_entropy,
        consonant_ratio=consonant_rat, digit_ratio=digit_ratio,
        special_char_ratio=special_ratio,
        min_brand_levenshtein=min_lev, brand_levenshtein_ratio=lev_ratio,
        tld_length=len(tld), domain_core_length=len(core),
    )


if __name__ == "__main__":
    samples = [
        ("http://192.168.1.1/login/verify?user=admin",      "PHISHING"),
        ("https://paypal-secure-login.com/update/password", "PHISHING"),
        ("https://paypol.com/login/confirm",                "PHISHING"),
        ("https://www.google.com/search?q=openai",          "LEGIT   "),
        ("https://github.com/huggingface/transformers",     "LEGIT   "),
        ("https://www.amazon.com/dp/B09JQMJHXY",            "LEGIT   "),
    ]
    print(f"\n{'URL':<52} {'True':8} {'Trusted':>7} {'IP':>3} {'Lev':>5} {'d_ent':>6} {'kw':>3}")
    print("─" * 85)
    for url, label in samples:
        f = extract_features(url)
        print(f"{url[:51]:<52} {label:8} {f.is_trusted_domain:>7} "
              f"{f.has_ip_address:>3} {f.min_brand_levenshtein:>5} "
              f"{f.domain_entropy:>6.2f} {f.has_phish_keyword:>3}")