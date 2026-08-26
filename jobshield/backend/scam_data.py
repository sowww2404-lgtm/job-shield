# scam_data.py
# Curated, hand-built dataset of scam-indicator phrases for job/internship and
# paid-course offers, with severity weights. This is a rule-based reference
# set (no external API needed) built from widely-reported scam patterns.

# HARD FLAGS: if ANY of these phrases appear, the result is auto-escalated
# to High risk regardless of anything else (money-ask / sensitive-data-ask).
HARD_FLAG_PHRASES = [
    "registration fee", "security deposit", "processing fee", "training kit fee",
    "refundable deposit", "pay to confirm", "pay for laptop", "activation fee",
    "send your bank details", "share your otp", "share otp", "aadhar number",
    "aadhaar number", "pan card number", "account number and ifsc",
    "upi pin", "cvv number", "pay ₹", "pay rs", "pay inr", "gpay to confirm",
    "advance payment to secure", "joining fee","remote access to your device",
    "processing fee to release"
]

# SOFT FLAGS: each hit adds weighted points toward the score, capped.
SOFT_FLAG_PHRASES = {
    # phrase: (weight, plain-language "why this matters" explanation)
    "urgent": (30, "Scammers create false urgency so you accept before checking facts."),
    "act now": (45, "Pressure to act immediately is a classic scam tactic."),
    "limited time offer": (40, "Real hiring rarely runs on a countdown clock."),
    "guaranteed job": (80, "No legitimate recruiter can guarantee a job outcome."),
    "100% placement": (80, "Guaranteed placement claims are a common course-scam promise."),
    "no interview required": (85, "Real jobs almost always involve some form of screening."),
    "work from home earn": (9, "Vague 'earn from home' pitches are a common scam template."),
    "limited seats": (25, "Manufactured scarcity is used to rush your decision."),
    "confidential": (5, "Legitimate offers don't usually ask you to keep them secret."),
    "whatsapp only": (75, "Real companies rarely conduct entire hiring only over chat apps."),
    "telegram only": (87, "Real companies rarely conduct entire hiring only over chat apps."),
    "no experience needed high salary": (10, "Unusually high pay for no experience is a red flag."),
    "dear candidate": (3, "Generic greetings suggest a mass-sent, unverified message."),
    "congratulations you have been selected": (7, "Being 'selected' without ever applying or interviewing is suspicious."),
    "click the link below to accept": (80, "Be cautious of offers that push you straight to a link."),
    "government certified": (5, "Vague certification claims should be independently verified."),
    "job guarantee": (70, "No genuine course or company can guarantee a job."),
    "refund if not satisfied": (4, "Vague refund promises are often unenforceable in practice."),
    "only today": (100, "Same-day pressure tactics are designed to stop you researching."),
    "free laptop": (6, "Offers bundling free hardware with a job are frequently scams."),
    "shortlisted for a remote role": (15, "Vague 'shortlisted' claims for a role you never applied to are a common templated scam opener."),
}
SAFE_SIGNAL_PHRASES = {
    "equal opportunity employer": (10, "This formal legal phrase is standard in genuine corporate job postings and is rarely used by scammers."),
    "years of experience": (-4, "Specific experience requirements are typical of genuine, detailed job descriptions."),
    "bachelor's degree": (-4, "Specific degree requirements are typical of genuine job postings."),
    "thank you for your interest": (-4, "Polite, formal acknowledgment language is common in real recruiting communications."),
}

# Suspicious top-level domains commonly abused for scam/phishing sites.
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".info"]

# Known URL shortener domains (obscure the real destination).
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "rebrand.ly", "shorturl.at", "cutt.ly",
]

# Phishing-adjacent keywords in a URL path/hostname itself.
URL_PHISHING_KEYWORDS = ["verify-account", "secure-login", "confirm-payment", "job-offer-claim", "hr-portal-verify"]
