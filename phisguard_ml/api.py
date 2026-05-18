# """
# PhishGuard — FastAPI Backend
# Serves the ML model over HTTP with two endpoints:

#   POST /scan          → scan a single URL
#   POST /scan/batch    → scan multiple URLs at once
#   GET  /history       → recent scan history
#   GET  /stats         → model info + accuracy metrics
#   GET  /health        → health check

# Install:
#     pip install fastapi uvicorn[standard] joblib scipy

# Run:
#     uvicorn api:app --reload --port 8000

# Test in browser:
#     http://localhost:8000/docs   ← interactive Swagger UI
# """

# import re
# import sys
# import json
# import time
# import uuid
# from pathlib import Path
# from datetime import datetime
# from collections import deque
# from urllib.parse import urlparse
# from contextlib import asynccontextmanager

# import joblib
# import numpy as np
# from scipy.sparse import hstack, csr_matrix

# from fastapi import FastAPI, HTTPException
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel, field_validator

# # Add ML folder to path so we can import feature_extractor
# sys.path.insert(0, str(Path(__file__).parent))
# from feature_extractor import extract_features, TRUSTED_DOMAINS

# # ── Paths ─────────────────────────────────────────────────────────────────────
# MODEL_DIR = Path(__file__).parent / "models"


# # ── Global model state (loaded once at startup) ───────────────────────────────
# class ModelStore:
#     model     = None
#     scaler    = None
#     tfidf_vec = None
#     meta      = {}

# store = ModelStore()

# # In-memory scan history (last 500 scans)
# history: deque = deque(maxlen=500)


# # ── Lifespan: load models on startup ─────────────────────────────────────────
# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     print("[startup] Loading models …")
#     try:
#         store.model     = joblib.load(MODEL_DIR / "xgb_model.joblib")
#         store.scaler    = joblib.load(MODEL_DIR / "scaler.joblib")
#         store.tfidf_vec = joblib.load(MODEL_DIR / "tfidf.joblib")
#         with open(MODEL_DIR / "meta.json") as f:
#             store.meta = json.load(f)
#         print(f"[startup] Models loaded. Accuracy: {store.meta['metrics']['accuracy']:.4f}")
#     except FileNotFoundError as e:
#         print(f"[startup] ERROR: {e}")
#         print("[startup] Run train.py first to generate model files.")
#     yield
#     print("[shutdown] Cleaning up …")


# # ── App ───────────────────────────────────────────────────────────────────────
# app = FastAPI(
#     title="PhishGuard API",
#     description="ML-powered phishing URL detection",
#     version="1.0.0",
#     lifespan=lifespan,
# )

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],        # tighten this in production
#     allow_methods=["*"],
#     allow_headers=["*"],
# )


# # ── Schemas ───────────────────────────────────────────────────────────────────
# class ScanRequest(BaseModel):
#     url: str

#     @field_validator("url")
#     @classmethod
#     def validate_url(cls, v):
#         v = v.strip()
#         if not v:
#             raise ValueError("URL cannot be empty")
#         if len(v) > 2048:
#             raise ValueError("URL too long (max 2048 chars)")
#         return v


# class BatchScanRequest(BaseModel):
#     urls: list[str]

#     @field_validator("urls")
#     @classmethod
#     def validate_urls(cls, v):
#         if not v:
#             raise ValueError("urls list cannot be empty")
#         if len(v) > 100:
#             raise ValueError("Max 100 URLs per batch request")
#         return [u.strip() for u in v]


# class ScanResult(BaseModel):
#     scan_id:    str
#     url:        str
#     label:      str          # "phishing" | "legit"
#     confidence: float        # 0.0 – 1.0  (P(phishing))
#     risk_level: str          # "HIGH" | "MEDIUM" | "LOW" | "SAFE"
#     reason:     str | None   # set if whitelist hit
#     scanned_at: str


# # ── Core prediction logic ─────────────────────────────────────────────────────
# def _predict(url: str) -> ScanResult:
#     if store.model is None:
#         raise HTTPException(status_code=503,
#                             detail="Model not loaded. Run train.py first.")

#     scan_id    = str(uuid.uuid4())[:8]
#     scanned_at = datetime.utcnow().isoformat() + "Z"
#     reason     = None

#     # ── Whitelist fast-path ───────────────────────────────────────────────────
#     try:
#         hostname = urlparse(url if "://" in url else "http://" + url).hostname or ""
#         bare     = re.sub(r"^www\.", "", hostname.lower())
#         if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
#             result = ScanResult(
#                 scan_id=scan_id, url=url, label="legit",
#                 confidence=0.0, risk_level="SAFE",
#                 reason="Trusted domain whitelist", scanned_at=scanned_at,
#             )
#             history.appendleft(result.model_dump())
#             return result
#     except Exception:
#         pass

#     # ── Feature extraction + inference ───────────────────────────────────────
#     try:
#         hand_feats = extract_features(url).to_vector()
#         X_hand     = store.scaler.transform([hand_feats])
#         X_tfidf    = store.tfidf_vec.transform([url])
#         X_combined = hstack([csr_matrix(X_hand), X_tfidf])

#         proba = float(store.model.predict_proba(X_combined)[0][1])
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Inference error: {e}")

#     label = "phishing" if proba >= 0.5 else "legit"
#     risk  = "HIGH" if proba > 0.80 else "MEDIUM" if proba > 0.50 else "LOW"

#     result = ScanResult(
#         scan_id=scan_id, url=url, label=label,
#         confidence=round(proba, 4), risk_level=risk,
#         reason=reason, scanned_at=scanned_at,
#     )
#     history.appendleft(result.model_dump())
#     return result


# # ── Routes ────────────────────────────────────────────────────────────────────

# @app.get("/health")
# def health():
#     return {
#         "status": "ok",
#         "model_loaded": store.model is not None,
#         "timestamp": datetime.utcnow().isoformat() + "Z",
#     }


# @app.get("/stats")
# def stats():
#     return {
#         "model": "XGBoost + TF-IDF char n-grams",
#         "n_features": (store.meta.get("n_hand_features", 0) +
#                        store.meta.get("n_tfidf_features", 0)),
#         "metrics": store.meta.get("metrics", {}),
#         "total_scans": len(history),
#         "phishing_detected": sum(1 for h in history if h["label"] == "phishing"),
#     }


# @app.post("/scan", response_model=ScanResult)
# def scan(req: ScanRequest):
#     """Scan a single URL for phishing."""
#     return _predict(req.url)


# @app.post("/scan/batch")
# def scan_batch(req: BatchScanRequest):
#     """Scan up to 100 URLs in one request."""
#     results = []
#     for url in req.urls:
#         try:
#             results.append(_predict(url))
#         except HTTPException as e:
#             results.append({"url": url, "error": e.detail})
#     return {"results": results, "total": len(results)}


# @app.get("/history")
# def get_history(limit: int = 50):
#     """Return the last N scans (default 50, max 500)."""
#     limit = min(limit, 500)
#     return {"scans": list(history)[:limit], "total": len(history)}


"""
PhishGuard — FastAPI Backend
Serves the ML model over HTTP with endpoints:

  POST /scan          → scan a single URL
  POST /scan/batch    → scan multiple URLs at once
  GET  /history       → recent scan history
  GET  /stats         → model info + accuracy metrics
  GET  /health        → health check

Install:
    pip install fastapi uvicorn[standard] joblib scipy requests python-whois dnspython

Run:
    uvicorn api:app --reload --port 8000
"""

import re
import sys
import json
import uuid
import socket
import requests
from pathlib import Path
from datetime import datetime
from collections import deque
from urllib.parse import urlparse, unquote
from contextlib import asynccontextmanager

import joblib
import numpy as np
from scipy.sparse import hstack, csr_matrix

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

sys.path.insert(0, str(Path(__file__).parent))
from feature_extractor import extract_features, TRUSTED_DOMAINS

# ── Paths ─────────────────────────────────────────────────────────────────────
MODEL_DIR = Path(__file__).parent / "models"

# ── CTI API Keys (set your keys here) ────────────────────────────────────────
VIRUSTOTAL_API_KEY = "e090d105d27ab1d67afca2a1b37db5462d7779aeca45eefdb8b324927f65286a"   # get free key at virustotal.com
URLHAUS_API        = "https://urlhaus-api.abuse.ch/v1/url/"

# ── Global model state ────────────────────────────────────────────────────────
class ModelStore:
    model     = None
    scaler    = None
    tfidf_vec = None
    meta      = {}

store = ModelStore()
history: deque = deque(maxlen=500)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[startup] Loading models …")
    try:
        store.model     = joblib.load(MODEL_DIR / "xgb_model.joblib")
        store.scaler    = joblib.load(MODEL_DIR / "scaler.joblib")
        store.tfidf_vec = joblib.load(MODEL_DIR / "tfidf.joblib")
        with open(MODEL_DIR / "meta.json") as f:
            store.meta = json.load(f)
        print(f"[startup] Models loaded. Accuracy: {store.meta['metrics']['accuracy']:.4f}")
    except FileNotFoundError as e:
        print(f"[startup] ERROR: {e}")
    yield
    print("[shutdown] Cleaning up …")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard API",
    description="ML-powered phishing URL detection with CTI",
    version="1.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2048:
            raise ValueError("URL too long (max 2048 chars)")
        return v


class BatchScanRequest(BaseModel):
    urls: list[str]

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, v):
        if not v:
            raise ValueError("urls list cannot be empty")
        if len(v) > 100:
            raise ValueError("Max 100 URLs per batch request")
        return [u.strip() for u in v]


class ScanResult(BaseModel):
    scan_id:              str
    url:                  str
    decoded_url:          str | None = None   # decoded version if obfuscated
    label:                str                 # "phishing" | "legit"
    confidence:           float
    risk_level:           str                 # "HIGH" | "MEDIUM" | "LOW" | "SAFE"
    reason:               str | None = None
    scanned_at:           str
    # CTI fields
    urlhaus_status:       str | None = None   # "online" | "offline" | "unknown"
    urlhaus_threat:       str | None = None
    virustotal_detected:  bool | None = None
    virustotal_positives: int | None = None
    virustotal_total:     int | None = None
    # Forensics fields
    domain_age_days:      int | None = None
    dns_resolved:         bool | None = None
    # Typosquat
    typosquat_target:     str | None = None
    typosquat_distance:   int | None = None


# ── CTI: URLhaus lookup ───────────────────────────────────────────────────────
def check_urlhaus(url: str) -> dict:
    try:
        resp = requests.post(
            URLHAUS_API,
            data={"url": url},
            timeout=4,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {
                    "urlhaus_status": data.get("url_status", "unknown"),
                    "urlhaus_threat": data.get("threat", None),
                }
            return {"urlhaus_status": "not_listed", "urlhaus_threat": None}
    except Exception:
        pass
    return {"urlhaus_status": "unavailable", "urlhaus_threat": None}


# ── CTI: VirusTotal lookup ────────────────────────────────────────────────────
def check_virustotal(url: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {
            "virustotal_detected": None,
            "virustotal_positives": None,
            "virustotal_total": None,
        }
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            return {
                "virustotal_detected": positives > 0,
                "virustotal_positives": positives,
                "virustotal_total": total,
            }
    except Exception:
        pass
    return {
        "virustotal_detected": None,
        "virustotal_positives": None,
        "virustotal_total": None,
    }


# ── Forensics: DNS resolve ────────────────────────────────────────────────────
def check_dns(hostname: str) -> bool | None:
    try:
        socket.setdefaulttimeout(3)
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False


# ── Forensics: WHOIS domain age ───────────────────────────────────────────────
def check_whois(hostname: str) -> int | None:
    try:
        import whois
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            age = (datetime.utcnow() - created).days
            return max(age, 0)
    except Exception:
        pass
    return None


# ── URL decoding ──────────────────────────────────────────────────────────────
def decode_url(url: str) -> tuple[str, bool]:
    """Decode percent-encoded URLs. Returns (decoded_url, was_encoded)."""
    decoded = unquote(url)
    return decoded, decoded != url


# ── Typosquat reason builder ──────────────────────────────────────────────────
def build_reason(features, label: str, proba: float,
                 urlhaus: dict, vt: dict) -> str:
    reasons = []

    if label == "phishing":
        if urlhaus.get("urlhaus_status") == "online":
            reasons.append(f"listed on URLhaus as {urlhaus.get('urlhaus_threat','malware')}")
        if vt.get("virustotal_detected"):
            reasons.append(
                f"flagged by {vt['virustotal_positives']}/{vt['virustotal_total']} VirusTotal engines"
            )
        if features.get("has_ip_address"):
            reasons.append("IP address used instead of domain")
        if features.get("has_phish_keyword"):
            reasons.append("phishing keywords detected in URL")
        if features.get("has_suspicious_tld"):
            reasons.append("suspicious TLD")
        if features.get("has_prefix_suffix"):
            reasons.append("brand name used as prefix/suffix")
        if features.get("min_brand_levenshtein", 999) <= 2:
            reasons.append("possible typosquatting of known brand")
        if features.get("has_shortener"):
            reasons.append("URL shortener detected")
        if not reasons:
            reasons.append(f"ML model: {round(proba*100)}% phishing probability")

    return "; ".join(reasons) if reasons else None


# ── Core prediction ───────────────────────────────────────────────────────────
def _predict(url: str) -> ScanResult:
    if store.model is None:
        raise HTTPException(status_code=503,
                            detail="Model not loaded. Run train.py first.")

    scan_id    = str(uuid.uuid4())[:8]
    scanned_at = datetime.utcnow().isoformat() + "Z"

    # ── URL decoding ──────────────────────────────────────────────────────────
    decoded_url, was_encoded = decode_url(url)
    scan_url = decoded_url  # use decoded URL for inference

    # ── Parse hostname ────────────────────────────────────────────────────────
    try:
        hostname = urlparse(
            scan_url if "://" in scan_url else "http://" + scan_url
        ).hostname or ""
        bare = re.sub(r"^www\.", "", hostname.lower())
    except Exception:
        hostname = ""
        bare = ""

    # ── Whitelist fast-path ───────────────────────────────────────────────────
    if bare in TRUSTED_DOMAINS or hostname in TRUSTED_DOMAINS:
        result = ScanResult(
            scan_id=scan_id, url=url,
            decoded_url=decoded_url if was_encoded else None,
            label="legit", confidence=0.0, risk_level="SAFE",
            reason="Trusted domain whitelist", scanned_at=scanned_at,
            dns_resolved=True,
        )
        history.appendleft(result.model_dump())
        return result

    # ── CTI lookups (run before inference so reason can include them) ─────────
    urlhaus = check_urlhaus(scan_url)
    vt      = check_virustotal(scan_url)

    # ── Forensics ─────────────────────────────────────────────────────────────
    dns_resolved    = check_dns(hostname) if hostname else None
    domain_age_days = check_whois(hostname) if hostname else None

    # ── Feature extraction + inference ───────────────────────────────────────
    try:
        feat_obj   = extract_features(scan_url)
        hand_feats = feat_obj.to_vector()
        feat_dict  = feat_obj.__dict__ if hasattr(feat_obj, "__dict__") else {}

        X_hand     = store.scaler.transform([hand_feats])
        X_tfidf    = store.tfidf_vec.transform([scan_url])
        X_combined = hstack([csr_matrix(X_hand), X_tfidf])
        proba      = float(store.model.predict_proba(X_combined)[0][1])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {e}")

    # ── Boost confidence if URLhaus listed ───────────────────────────────────
    if urlhaus.get("urlhaus_status") == "online":
        proba = max(proba, 0.95)

    label = "phishing" if proba >= 0.5 else "legit"
    risk  = "HIGH" if proba > 0.80 else "MEDIUM" if proba > 0.50 else "LOW"
    if label == "legit":
        risk = "SAFE" if proba < 0.2 else "LOW"

    # ── Typosquat info ────────────────────────────────────────────────────────
    typosquat_target   = None
    typosquat_distance = None
    lev = feat_dict.get("min_brand_levenshtein", 999)
    if isinstance(lev, (int, float)) and lev <= 2 and label == "phishing":
        typosquat_distance = int(lev)
        typosquat_target   = "known brand (see levenshtein features)"

    reason = build_reason(feat_dict, label, proba, urlhaus, vt)

    result = ScanResult(
        scan_id=scan_id,
        url=url,
        decoded_url=decoded_url if was_encoded else None,
        label=label,
        confidence=round(proba, 4),
        risk_level=risk,
        reason=reason,
        scanned_at=scanned_at,
        urlhaus_status=urlhaus.get("urlhaus_status"),
        urlhaus_threat=urlhaus.get("urlhaus_threat"),
        virustotal_detected=vt.get("virustotal_detected"),
        virustotal_positives=vt.get("virustotal_positives"),
        virustotal_total=vt.get("virustotal_total"),
        domain_age_days=domain_age_days,
        dns_resolved=dns_resolved,
        typosquat_target=typosquat_target,
        typosquat_distance=typosquat_distance,
    )
    history.appendleft(result.model_dump())
    return result


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": store.model is not None,
        "cti_urlhaus": True,
        "cti_virustotal": bool(VIRUSTOTAL_API_KEY),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/stats")
def stats():
    return {
        "model": "XGBoost + TF-IDF char n-grams",
        "n_features": (store.meta.get("n_hand_features", 0) +
                       store.meta.get("n_tfidf_features", 0)),
        "metrics": store.meta.get("metrics", {}),
        "total_scans": len(history),
        "phishing_detected": sum(1 for h in history if h["label"] == "phishing"),
    }


@app.post("/scan", response_model=ScanResult)
def scan(req: ScanRequest):
    """Scan a single URL for phishing with CTI enrichment."""
    return _predict(req.url)


@app.post("/scan/batch")
def scan_batch(req: BatchScanRequest):
    """Scan up to 100 URLs in one request."""
    results = []
    for url in req.urls:
        try:
            results.append(_predict(url))
        except HTTPException as e:
            results.append({"url": url, "error": e.detail})
    return {"results": results, "total": len(results)}


@app.get("/history")
def get_history(limit: int = 50):
    limit = min(limit, 500)
    return {"scans": list(history)[:limit], "total": len(history)}