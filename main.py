"""
Verity Backend - Session 2
Added: Google Safe Browsing API, Spamhaus DBL, SURBL domain reputation
Fixed: em dashes replaced with regular hyphens throughout
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import re
import os
import asyncio
import dns.resolver
from datetime import datetime, timezone
from typing import Optional

app = FastAPI(title="Verity API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

SAFE_BROWSING_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
RDAP_BASE = "https://rdap.org/domain/"


# --- Models ------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    domain: str
    subject: Optional[str] = ""
    urls: Optional[list[str]] = []  # URLs extracted from email body


class DomainAgeResult(BaseModel):
    domain: str
    age_days: Optional[int]
    created_date: Optional[str]
    severity: int
    reason: Optional[str]


class NLPResult(BaseModel):
    severity: int
    flags: list[str]


class SafeBrowsingResult(BaseModel):
    threats_found: int
    threat_urls: list[str]
    severity: int
    reason: Optional[str]


class ReputationResult(BaseModel):
    spamhaus_listed: bool
    surbl_listed: bool
    severity: int
    reason: Optional[str]


class AnalyzeResponse(BaseModel):
    domain: str
    domainAge: DomainAgeResult
    nlpSignals: NLPResult
    safeBrowsing: SafeBrowsingResult
    reputation: ReputationResult


# --- Domain Age (RDAP) -------------------------------------------------------

async def get_domain_age(domain: str) -> DomainAgeResult:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{RDAP_BASE}{domain}")
            if resp.status_code != 200:
                return DomainAgeResult(domain=domain, age_days=None, created_date=None, severity=0, reason="WHOIS unavailable")

            data = resp.json()
            created_date = None

            for event in data.get("events", []):
                if event.get("eventAction") in ("registration", "registration date"):
                    created_date = event.get("eventDate")
                    break

            if not created_date:
                return DomainAgeResult(domain=domain, age_days=None, created_date=None, severity=0, reason="Creation date not found")

            created_dt = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days

            severity = 0
            reason = None

            if age_days < 30:
                severity = 30
                reason = f"Domain is only {age_days} days old - very high risk"
            elif age_days < 90:
                severity = 25
                reason = f"Domain is only {age_days} days old"
            elif age_days < 180:
                severity = 15
                reason = f"Domain created {age_days} days ago (under 6 months)"
            elif age_days < 365:
                severity = 8
                reason = f"Domain is less than 1 year old ({age_days} days)"

            return DomainAgeResult(
                domain=domain,
                age_days=age_days,
                created_date=created_date[:10],
                severity=severity,
                reason=reason,
            )

    except Exception as e:
        return DomainAgeResult(domain=domain, age_days=None, created_date=None, severity=0, reason=f"Lookup failed: {str(e)[:60]}")


# --- NLP Analysis ------------------------------------------------------------

URGENCY_PATTERNS = [
    (r"\burgent\b", "Urgency trigger: urgent", 8),
    (r"\bimmediately\b", "Time pressure: immediately", 8),
    (r"action required", "Action demand", 10),
    (r"verify your (account|identity|email|payment)", "Account verification request", 12),
    (r"(account|service).{0,20}(suspended|compromised|locked)", "Account suspension threat", 15),
    (r"limited time offer", "Artificial scarcity", 6),
    (r"expires? (today|soon|in \d+ hours?)", "Expiry pressure", 8),
    (r"click here (to|and)", "Generic click-bait", 6),
    (r"(confirm|update|verify) your (billing|payment|card|info)", "Financial info request", 12),
    (r"you (have been|are) selected", "False personalization", 8),
    (r"congratulations.{0,30}won", "Prize scam pattern", 15),
    (r"\$[\d,]+.{0,20}(prize|reward|won|claim)", "Prize money mention", 15),
    (r"claim your (prize|reward|gift|money)", "Claim bait", 12),
    (r"unusual (sign.in|activity|login)", "Security false alarm", 10),
    (r"your (account|password).{0,20}(will be|has been).{0,20}(deleted|closed|suspended)", "Account deletion threat", 15),
    (r"we noticed.{0,30}attempt", "Suspicious activity claim", 10),
    (r"don'?t (ignore|delay|wait)", "Urgency pressure", 8),
    (r"final (notice|warning|reminder)", "Final warning pressure", 12),
    (r"security alert", "Security alert", 10),
    (r"unauthorized access", "Unauthorized access claim", 12),
    (r"kindly (verify|confirm|update)", "Phishing politeness pattern", 10),
    (r"dear (customer|user|member|account holder)", "Generic salutation", 8),
]


def analyze_nlp(text: str) -> NLPResult:
    if not text:
        return NLPResult(severity=0, flags=[])

    text_lower = text.lower()
    flags = []
    total_severity = 0

    for pattern, label, weight in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            flags.append(label)
            total_severity += weight

    return NLPResult(severity=min(30, total_severity), flags=flags[:5])


# --- Google Safe Browsing ----------------------------------------------------

async def check_safe_browsing(urls: list[str]) -> SafeBrowsingResult:
    """
    Check URLs against Google Safe Browsing API v4.
    Catches phishing, malware, and unwanted software URLs in real time.
    """
    empty = SafeBrowsingResult(threats_found=0, threat_urls=[], severity=0, reason=None)

    if not SAFE_BROWSING_KEY or not urls:
        return empty

    # Filter to real HTTP URLs only
    clean_urls = [u for u in urls if u.startswith(('http://', 'https://')) and len(u) < 2048]
    if not clean_urls:
        return empty

    payload = {
        "client": {"clientId": "verity-extension", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in clean_urls[:100]],  # API limit
        },
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{SAFE_BROWSING_URL}?key={SAFE_BROWSING_KEY}",
                json=payload,
            )
            if resp.status_code != 200:
                return empty

            data = resp.json()
            matches = data.get("matches", [])

            if not matches:
                return empty

            threat_urls = list({m.get("threat", {}).get("url", "") for m in matches if m.get("threat", {}).get("url")})
            threat_types = list({m.get("threatType", "") for m in matches})

            severity = min(len(matches) * 30, 50)  # hard hit per match

            return SafeBrowsingResult(
                threats_found=len(matches),
                threat_urls=threat_urls[:3],
                severity=severity,
                reason=f"Google flagged {len(matches)} URL(s) as {', '.join(threat_types).lower().replace('_', ' ')}",
            )

    except Exception as e:
        return empty


# --- Spamhaus DBL + SURBL Reputation -----------------------------------------

async def check_domain_reputation(domain: str) -> ReputationResult:
    """
    Query Spamhaus DBL and SURBL via DNS lookup.
    These are free threat intel feeds used by major email providers.
    No API key needed - pure DNS queries.
    """
    result = ReputationResult(spamhaus_listed=False, surbl_listed=False, severity=0, reason=None)

    # Clean domain - strip www and subdomains for root domain lookup
    parts = domain.split('.')
    root_domain = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

    async def dns_lookup(hostname: str) -> bool:
        """Returns True if the domain is listed (DNS lookup returns a result)."""
        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: dns.resolver.resolve(hostname, 'A')
            )
            return True  # Got a response = listed
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, Exception):
            return False  # NXDOMAIN = not listed (normal/clean)

    # Spamhaus DBL - domain blocklist
    spamhaus_query = f"{root_domain}.dbl.spamhaus.org"
    # SURBL - spam URI real-time blocklist
    surbl_query = f"{root_domain}.multi.surbl.org"

    spamhaus_listed, surbl_listed = await asyncio.gather(
        dns_lookup(spamhaus_query),
        dns_lookup(surbl_query),
    )

    result.spamhaus_listed = spamhaus_listed
    result.surbl_listed = surbl_listed

    if spamhaus_listed and surbl_listed:
        result.severity = 45
        result.reason = f"{domain} is listed on both Spamhaus DBL and SURBL - known spam/phishing domain"
    elif spamhaus_listed:
        result.severity = 35
        result.reason = f"{domain} is listed on Spamhaus DBL - known spam domain"
    elif surbl_listed:
        result.severity = 30
        result.reason = f"{domain} is listed on SURBL - known malicious domain"

    return result


# --- Routes ------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "Verity API", "version": "2.0.0"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    if not req.domain or len(req.domain) > 255:
        raise HTTPException(status_code=400, detail="Invalid domain")

    domain = req.domain.lower().strip().lstrip("www.")

    # Run all checks concurrently
    domain_age, nlp, safe_browsing, reputation = await asyncio.gather(
        get_domain_age(domain),
        asyncio.to_thread(analyze_nlp, req.subject or ""),
        check_safe_browsing(req.urls or []),
        check_domain_reputation(domain),
    )

    return AnalyzeResponse(
        domain=domain,
        domainAge=domain_age,
        nlpSignals=nlp,
        safeBrowsing=safe_browsing,
        reputation=reputation,
    )
