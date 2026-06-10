"""
Verity Backend — FastAPI
Provides: domain age WHOIS lookup + NLP phishing analysis
Deploy free on Render.com
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
import re
import json
from datetime import datetime, timezone
from typing import Optional

app = FastAPI(title="Verity API", version="1.0.0")

# Allow Chrome extension origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict to your extension ID in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ─── Models ──────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    domain: str
    subject: Optional[str] = ""


class DomainAgeResult(BaseModel):
    domain: str
    age_days: Optional[int]
    created_date: Optional[str]
    severity: int  # 0-30 deduction
    reason: Optional[str]


class NLPResult(BaseModel):
    severity: int  # 0-30
    flags: list[str]


class AnalyzeResponse(BaseModel):
    domain: str
    domainAge: DomainAgeResult
    nlpSignals: NLPResult


# ─── Domain Age (WHOIS) ───────────────────────────────────────────────────────

WHOIS_API = "https://www.whoisxmlapi.com/whoisserver/WhoisService"
# Free alternative — no API key needed:
RDAP_BASE = "https://rdap.org/domain/"


async def get_domain_age(domain: str) -> DomainAgeResult:
    """
    Query RDAP (free, no API key) to get domain creation date.
    Falls back gracefully if unavailable.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{RDAP_BASE}{domain}")
            if resp.status_code != 200:
                return DomainAgeResult(domain=domain, age_days=None, created_date=None, severity=0, reason="WHOIS unavailable")

            data = resp.json()

            # RDAP events contain registration date
            created_date = None
            for event in data.get("events", []):
                if event.get("eventAction") in ("registration", "registration date"):
                    created_date = event.get("eventDate")
                    break

            if not created_date:
                return DomainAgeResult(domain=domain, age_days=None, created_date=None, severity=0, reason="Creation date not found")

            # Parse ISO date
            created_dt = datetime.fromisoformat(created_date.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - created_dt).days

            severity = 0
            reason = None

            if age_days < 30:
                severity = 30
                reason = f"Domain is only {age_days} days old — very high risk"
            elif age_days < 90:
                severity = 25
                reason = f"Domain is only {age_days} days old"
            elif age_days < 180:
                severity = 15
                reason = f"Domain created {age_days} days ago (< 6 months)"
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


# ─── NLP Analysis ────────────────────────────────────────────────────────────

URGENCY_PATTERNS = [
    (r"\burgent\b", "Urgency trigger: 'urgent'", 8),
    (r"\bimmediately\b", "Time pressure: 'immediately'", 8),
    (r"action required", "Action demand", 10),
    (r"verify your (account|identity|email|payment)", "Account verification request", 12),
    (r"(account|service).{0,20}(suspended|compromised|locked)", "Threat of account suspension", 15),
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
]


def analyze_nlp(text: str) -> NLPResult:
    """
    Rule-based NLP analysis. No paid API needed.
    Returns severity (0-30) and matched flags.
    """
    if not text:
        return NLPResult(severity=0, flags=[])

    text_lower = text.lower()
    flags = []
    total_severity = 0

    for pattern, label, weight in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            flags.append(label)
            total_severity += weight

    return NLPResult(
        severity=min(30, total_severity),
        flags=flags[:5],  # Return top 5 flags
    )


# ─── Routes ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "Verity API"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest):
    if not req.domain or len(req.domain) > 255:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Clean domain input
    domain = req.domain.lower().strip().lstrip("www.")

    # Run domain age + NLP concurrently
    import asyncio
    domain_age, nlp = await asyncio.gather(
        get_domain_age(domain),
        asyncio.to_thread(analyze_nlp, req.subject or ""),
    )

    return AnalyzeResponse(
        domain=domain,
        domainAge=domain_age,
        nlpSignals=nlp,
    )
