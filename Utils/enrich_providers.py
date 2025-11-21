# Utils/enrich_providers.py
import requests
from datetime import datetime
from config import Config

# All provider wrappers should return a canonical dict:
# {
#   "source": "<name>",
#   "raw": {...} or None,
#   "error": "<string>" optional,
#   "score": float 0..100 optional,
#   "tags": [ ... ],
#   "classification": "<string>" optional,
#   "retrieved_at": datetime
# }

def greynoise_lookup_ip(ip, timeout=6):
    """Use community endpoint if no key; if key present, use enterprise endpoint."""
    key = getattr(Config, "GRAYNOISE_API_KEY", None)
    headers = {}
    if key:
        headers["Key"] = key
        url = f"https://api.greynoise.io/v2/noise/context/{ip}"
    else:
        # community endpoint (v3 community) - note: it may return 404 for unknown IPs
        url = f"https://api.greynoise.io/v3/community/{ip}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # classification: greynoise uses "classification" or community returns "classification"
            cls = data.get("classification") if isinstance(data, dict) else None
            return {"source": "GreyNoise", "raw": data, "classification": cls, "retrieved_at": datetime.utcnow()}
        return {"source": "GreyNoise", "error": f"HTTP {r.status_code}", "text": r.text[:1000], "retrieved_at": datetime.utcnow()}
    except Exception as e:
        return {"source": "GreyNoise", "error": "exception", "text": str(e)}

def otx_lookup_ip(ip, timeout=6):
    """AlienVault OTX general indicator API for IPv4"""
    key = getattr(Config, "OTX_API_KEY", None)
    headers = {}
    if key:
        headers["X-OTX-API-KEY"] = key
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # presence of pulses indicates community sightings
            pulses = data.get("pulse_info", {})
            return {"source": "OTX", "raw": data, "score": (1 if pulses and pulses.get("count", 0) > 0 else 0)*100, "tags": [], "retrieved_at": datetime.utcnow()}
        return {"source": "OTX", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except Exception as e:
        return {"source": "OTX", "error": "exception", "text": str(e)}

def urlhaus_lookup(url_to_check, timeout=8):
    """URLhaus lookup via abuse.ch public API (POST)"""
    api = "https://urlhaus-api.abuse.ch/v1/url/"
    try:
        r = requests.post(api, data={"url": url_to_check}, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # urlhaus returns { "query_status": "ok", "url": {...} } when found
            # treat ok->malicious
            q = data.get("query_status")
            score = 100 if q == "ok" else 0
            return {"source": "URLhaus", "raw": data, "score": score, "retrieved_at": datetime.utcnow()}
        return {"source": "URLhaus", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except Exception as e:
        return {"source": "URLhaus", "error": "exception", "text": str(e)}

def abusech_lookup_hash(hashval, timeout=8):
    """Abuse.ch ThreatFox / MalwareBazaar wrappers can be added similarly"""
    # Example placeholder: implement if you need file-hash lookups
    return {"source": "AbuseCh", "error": "not_implemented"}

def ipqs_lookup_ip(ip, timeout=6):
    key = getattr(Config, "IPQS_API_KEY", None)
    if not key:
        return {"source": "IPQS", "error": "no_api_key"}
    url = f"https://ipqualityscore.com/api/json/ip/{key}/{ip}"
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            # ipqs returns fraud_score 0..100, and fields like proxy, tor
            score = data.get("fraud_score") or 0
            tags = []
            if data.get("proxy"): tags.append("proxy")
            if data.get("tor"): tags.append("tor")
            if data.get("bot_status"): tags.append("bot")
            return {"source": "IPQS", "raw": data, "score": float(score), "tags": tags, "retrieved_at": datetime.utcnow()}
        return {"source": "IPQS", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except Exception as e:
        return {"source": "IPQS", "error": "exception", "text": str(e)}

def abuseipdb_lookup_wrapper(ip, timeout=10):
    """Reuse the existing abuseipdb_lookup in tasks.py or call here if desired.
       This wrapper ensures canonical output shape."""
    from tasks import abuseipdb_lookup  # local import to avoid circular at module load
    r = abuseipdb_lookup(ip, timeout=timeout)
    # map fields
    if r.get("raw") and isinstance(r["raw"], dict):
        data = r["raw"].get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        tags = []
        return {"source": "AbuseIPDB", "raw": r["raw"], "score": float(score), "tags": tags, "total_reports": total_reports, "retrieved_at": datetime.utcnow()}
    return r

# Generic domain lookup helpers (could use VirusTotal domain, or abuse.ch for domains)
def urlscan_lookup_wrapper(url_to_check, timeout=12):
    from tasks import urlscan_lookup
    return urlscan_lookup(url_to_check, timeout=timeout)
