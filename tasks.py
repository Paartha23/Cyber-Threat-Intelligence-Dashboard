# tasks.py
import requests
from config import Config
from models import upsert_ioc, lookups, iocs
from Utils.enrichment import compute_severity_from_results
from Utils.enrich_providers import (
    greynoise_lookup_ip,
    otx_lookup_ip,
    urlhaus_lookup,
    ipqs_lookup_ip,
    abuseipdb_lookup_wrapper,
    urlscan_lookup_wrapper
)

from datetime import datetime
import time


# -------------------------
# AbuseIPDB (safe)
# -------------------------
def abuseipdb_lookup(ip, timeout=10):
    key = Config.ABUSEIPDB_API_KEY
    if not key:
        return {"source": "AbuseIPDB", "error": "no_api_key"}

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Accept": "application/json", "Key": key}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 200:
            return {"source": "AbuseIPDB", "raw": r.json(), "retrieved_at": datetime.utcnow()}
        return {"source": "AbuseIPDB", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except requests.exceptions.Timeout:
        return {"source": "AbuseIPDB", "error": "timeout", "text": f"Timed out after {timeout}s"}
    except requests.exceptions.ConnectionError as e:
        return {"source": "AbuseIPDB", "error": "connection_error", "text": str(e)}
    except Exception as e:
        return {"source": "AbuseIPDB", "error": "exception", "text": str(e)}


# -------------------------
# VirusTotal - IP
# -------------------------
def virustotal_lookup_ip(ip, timeout=10):
    key = Config.VIRUSTOTAL_API_KEY
    if not key:
        return {"source": "VirusTotal", "error": "no_api_key"}

    headers = {"x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return {"source": "VirusTotal", "raw": r.json(), "retrieved_at": datetime.utcnow()}
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except requests.exceptions.Timeout:
        return {"source": "VirusTotal", "error": "timeout", "text": f"Timed out after {timeout}s"}
    except requests.exceptions.ConnectionError as e:
        return {"source": "VirusTotal", "error": "connection_error", "text": str(e)}
    except Exception as e:
        return {"source": "VirusTotal", "error": "exception", "text": str(e)}


# -------------------------
# VirusTotal - Domain
# -------------------------
def virustotal_lookup_domain(domain, timeout=10):
    key = Config.VIRUSTOTAL_API_KEY
    if not key:
        return {"source": "VirusTotal", "error": "no_api_key"}

    headers = {"x-apikey": key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return {"source": "VirusTotal", "raw": r.json(), "retrieved_at": datetime.utcnow()}
        return {"source": "VirusTotal", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}
    except Exception as e:
        return {"source": "VirusTotal", "error": "exception", "text": str(e)}


# -------------------------
# VirusTotal - URL
# -------------------------
def virustotal_lookup_url(url_to_check, timeout=10, poll_interval=1, max_poll=6):
    key = Config.VIRUSTOTAL_API_KEY
    if not key:
        return {"source": "VirusTotal", "error": "no_api_key"}

    headers = {"x-apikey": key}
    post_url = "https://www.virustotal.com/api/v3/urls"

    try:
        r = requests.post(post_url, headers=headers, data={"url": url_to_check}, timeout=timeout)
        if r.status_code not in (200, 201):
            return {"source": "VirusTotal", "error": f"POST HTTP {r.status_code}", "text": r.text[:1000]}

        resp = r.json()
        analysis_id = resp.get("data", {}).get("id")

        if not analysis_id:
            return {"source": "VirusTotal", "raw_post_response": resp, "note": "no_analysis_id_returned"}

        analyses_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        # Poll for results
        for _ in range(max_poll):
            ra = requests.get(analyses_url, headers=headers, timeout=timeout)
            if ra.status_code == 200:
                result_json = ra.json()
                status = result_json.get("data", {}).get("attributes", {}).get("status")
                if status in ("completed", "finished", "completed_with_failure"):
                    return {"source": "VirusTotal", "raw": result_json, "retrieved_at": datetime.utcnow()}
            time.sleep(poll_interval)

        return {"source": "VirusTotal", "error": "timeout_polling"}

    except Exception as e:
        return {"source": "VirusTotal", "error": "exception", "text": str(e)}


# -------------------------
# urlscan.io lookup
# -------------------------
def urlscan_lookup(target_url, timeout=15):
    key = getattr(Config, "URLSCAN_API_KEY", None)
    if not key:
        return {"source": "urlscan", "error": "no_api_key"}

    headers = {"API-Key": key, "Content-Type": "application/json"}
    post_url = "https://urlscan.io/api/v1/scan/"

    try:
        r = requests.post(post_url, json={"url": target_url, "public": "on"}, headers=headers, timeout=timeout)
        if r.status_code not in (200, 201):
            return {"source": "urlscan", "error": f"HTTP {r.status_code}", "text": r.text[:1000]}

        resp = r.json()
        result_api = resp.get("api")
        if result_api:
            rr = requests.get(result_api, timeout=timeout)
            if rr.status_code == 200:
                return {"source": "urlscan", "raw": rr.json(), "retrieved_at": datetime.utcnow()}
        return {"source": "urlscan", "raw_post": resp}
    except Exception as e:
        return {"source": "urlscan", "error": "exception", "text": str(e)}


# -------------------------
# MAIN ENRICHMENT (TinyDB-SAFE) with extra providers
# -------------------------
def enrich_ioc(lookup_id, ioc_type, value):

    # mark lookup running
    lookups.update_one(
        {"_id": lookup_id},
        {"$set": {"status": "running", "started_at": datetime.utcnow()}}
    )

    results = []

    try:
        # ------------------------------
        # Run provider lookups
        # ------------------------------
        if ioc_type == "ip":
            # built-in providers
            try:
                results.append(abuseipdb_lookup(value))
            except Exception as e:
                results.append({"source": "AbuseIPDB", "error": "exception", "text": str(e)})

            try:
                results.append(virustotal_lookup_ip(value))
            except Exception as e:
                results.append({"source": "VirusTotal", "error": "exception", "text": str(e)})

            # additional free providers (Greynoise, OTX, IPQS)
            try:
                results.append(greynoise_lookup_ip(value))
            except Exception as e:
                results.append({"source": "GreyNoise", "error": "exception", "text": str(e)})

            try:
                results.append(otx_lookup_ip(value))
            except Exception as e:
                results.append({"source": "OTX", "error": "exception", "text": str(e)})

            try:
                results.append(ipqs_lookup_ip(value))
            except Exception as e:
                results.append({"source": "IPQS", "error": "exception", "text": str(e)})

            # canonical abuseipdb wrapper to normalize fields (optional duplicate ok)
            try:
                results.append(abuseipdb_lookup_wrapper(value))
            except Exception:
                pass

        elif ioc_type == "domain":
            try:
                results.append(virustotal_lookup_domain(value))
            except Exception as e:
                results.append({"source": "VirusTotal", "error": "exception", "text": str(e)})

            try:
                results.append(urlscan_lookup_wrapper("https://" + value))
            except Exception:
                pass

        elif ioc_type == "url":
            try:
                results.append(virustotal_lookup_url(value))
            except Exception as e:
                results.append({"source": "VirusTotal", "error": "exception", "text": str(e)})

            try:
                results.append(urlscan_lookup_wrapper(value))
            except Exception as e:
                results.append({"source": "urlscan", "error": "exception", "text": str(e)})

            try:
                results.append(urlhaus_lookup(value))
            except Exception as e:
                results.append({"source": "URLhaus", "error": "exception", "text": str(e)})

        else:
            results.append({"source": "note", "info": "enrichment not implemented for this IOC type"})

        # ------------------------------
        # Store RAW results (append each provider output)
        # ------------------------------
        for r in results:
            try:
                upsert_ioc(ioc_type, value, r)
            except Exception:
                # don't break on storage error
                pass

        # ------------------------------
        # Compute severity + score
        # ------------------------------
        meta = compute_severity_from_results(results)

        # also store scoring as a source so UI can show per-source contributions
        try:
            upsert_ioc(ioc_type, value, {"source": "scoring", "meta": meta}, meta=meta)
        except Exception:
            pass

        # ------------------------------
        # TinyDB-SAFE UPSERT meta into canonical iocs collection
        # ------------------------------
        existing = iocs.find_one({"ioc_type": ioc_type, "value": value})

        if not existing:
            iocs.insert_one({
                "ioc_type": ioc_type,
                "value": value,
                "last_seen": datetime.utcnow(),
                "severity": None,
                "score": 0,
                "is_malicious": False,
                "score_details": {},
                "sources": []
            })

        # Now update canonical fields
        iocs.update_one(
            {"ioc_type": ioc_type, "value": value},
            {"$set": {
                "last_seen": datetime.utcnow(),
                "severity": meta.get("severity"),
                "score": meta.get("score"),
                "is_malicious": (meta.get("severity") == "malicious"),
                "score_details": meta.get("details")
            }}
        )

        # Done
        lookups.update_one(
            {"_id": lookup_id},
            {"$set": {"status": "done", "results": results, "finished_at": datetime.utcnow()}}
        )

    except Exception as e:
        lookups.update_one(
            {"_id": lookup_id},
            {"$set": {"status": "error", "error": str(e), "finished_at": datetime.utcnow()}}
        )
        raise
