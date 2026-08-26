# scoring.py
# Rule-based risk scoring: no ML model dependency needed, keeps the app
# actually runnable without training data or GPU/cloud costs.

import re
from difflib import SequenceMatcher
from scam_data import (
    HARD_FLAG_PHRASES,
    SOFT_FLAG_PHRASES,
    SAFE_SIGNAL_PHRASES,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    URL_PHISHING_KEYWORDS,
)
from verified_companies import VERIFIED_COMPANIES


def level_from_score(score):
    if score >= 70:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def check_text(text, mode="job"):
    """mode: 'job' or 'course'. Returns dict with score, level, flags."""
    lower = text.lower()
    flags = []
    score = 0
    hard_hit = False

    for phrase in HARD_FLAG_PHRASES:
        if phrase in lower:
            hard_hit = True
            flags.append(
                {
                    "label": f'Mentions "{phrase}"',
                    "why": "Asking for money or sensitive personal data before a formal hire is the single biggest scam signal.",
                    "weight": 40,
                }
            )

    for phrase, (weight, why) in SOFT_FLAG_PHRASES.items():
        if phrase in lower:
            score += weight
            flags.append({"label": f'Mentions "{phrase}"', "why": why, "weight": weight})
    for phrase, (weight, why) in SAFE_SIGNAL_PHRASES.items():
        if phrase in lower:
            score += weight  # weight is negative here
            flags.append({"label": f'Genuine-sounding: "{phrase}" ✅', "why": why, "weight": weight})        

    # Course-mode specific nudge: unrealistic low price + guarantee combo
    if mode == "course" and re.search(r"[₹$]\s?\d{2,4}\b", text) and "guarantee" in lower:
        score += 25
        flags.append(
            {
                "label": "Very low price bundled with a guarantee",
                "why": "Cheap price + guaranteed outcome is a common paid-course scam combination.",
                "weight": 25,
            }
        )

    if hard_hit:
        score = max(score, 80)

    score = max(0,min(score, 100))
    return {"score": score, "level": level_from_score(score), "flags": flags}


def _domain_from_url(url):
    url = url.strip()
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    url = url.split("/")[0]
    url = url.split("?")[0]
    return url.lower()


def _is_ip_literal(host):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host))


def _typosquat_match(host):
    """Compare host against known real domains; flag close-but-not-exact matches."""
    base = host.split(":")[0]
    for name, real_domain in VERIFIED_COMPANIES.items():
        if base == real_domain:
            return {"exact": True, "company": name, "real_domain": real_domain}
        similarity = SequenceMatcher(None, base, real_domain).ratio()
        if similarity > 0.80:
            return {"exact": False, "company": name, "real_domain": real_domain, "similarity": round(similarity, 2)}
    return None


def check_link(url):
    host = _domain_from_url(url)
    flags = []
    score = 0

    if not url.lower().startswith("https://"):
        score += 12
        flags.append({"label": "No HTTPS", "why": "Legitimate company sites almost always use secure HTTPS.", "weight": 12})

    if _is_ip_literal(host.split(":")[0]):
        score += 30
        flags.append({"label": "Raw IP address instead of a domain", "why": "Real companies use a named domain, not a bare IP address.", "weight": 30})

    for shortener in URL_SHORTENERS:
        if shortener in host:
            score += 20
            flags.append({"label": "Uses a link shortener", "why": "Shorteners hide the real destination site.", "weight": 20})
            break

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 20
            flags.append({"label": f"Uses a {tld} domain", "why": "This domain ending is frequently abused for scam/phishing sites.", "weight": 20})
            break

    if host.count(".") >= 3:
        score += 10
        flags.append({"label": "Unusually many subdomains", "why": "Excess subdomains are sometimes used to disguise the real host.", "weight": 10})

    for kw in URL_PHISHING_KEYWORDS:
        if kw in url.lower():
            score += 15
            flags.append({"label": f'Contains "{kw}"', "why": "This phrase is commonly used in phishing links.", "weight": 15})

    match = _typosquat_match(host)
    verified_match = None
    if match:
        if match["exact"]:
            verified_match = match["company"]
            score = max(0, score - 15)
            flags.append({"label": f"Matches known domain for {match['company'].title()} ✅", "why": "This domain matches a verified real company domain.", "weight": -15})
        else:
            score += 35
            flags.append(
                {
                    "label": f"Looks like a copycat of {match['company'].title()}'s real domain ({match['real_domain']})",
                    "why": "This domain is very similar to, but not exactly, a known real company domain — a classic typosquat pattern.",
                    "weight": 35,
                }
            )

    # Placeholders for real-time API checks — see README "Your Part of the Work"
    # to plug in real keys:
    #   - Google Safe Browsing API: flags known malicious/phishing URLs
    #   - WHOIS API: flags domains registered very recently (< 30 days)

    score = max(0, min(score, 100))
    return {"score": score, "level": level_from_score(score), "flags": flags, "verified_match": verified_match, "domain": host}
