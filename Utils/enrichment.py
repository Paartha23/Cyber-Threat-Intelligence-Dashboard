# Utils/enrichment.py
from datetime import datetime

def _find(results, name):
    for r in results:
        if r.get("source", "").lower() == name.lower():
            return r
    return None

def compute_severity_from_results(results):
    total = 0.0
    max_total = 0.0
    details = {}

    # Weight table (easy to tune)
    WEIGHT = {
        "virustotal": 4,
        "abuseipdb": 3,
        "greynoise": 2,
        "otx": 2,
        "urlhaus": 3,
        "ipqs": 2,
    }

    # ---------------------------
    # VirusTotal
    # ---------------------------
    vt = _find(results, "VirusTotal")
    if vt and vt.get("raw"):
        stats = vt["raw"].get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        m = stats.get("malicious", 0)
        s = stats.get("suspicious", 0)
        t = sum(stats.values()) or 1
        pct = ((m + 0.5 * s) / t) * 100

        w = WEIGHT["virustotal"]
        total += pct * w
        max_total += 100 * w

        details["VirusTotal"] = {"malicious": m, "suspicious": s, "total": t, "pct": pct}

    # ---------------------------
    # AbuseIPDB
    # ---------------------------
    ab = _find(results, "AbuseIPDB")
    if ab and ab.get("abuse_confidence") is not None:
        ac = float(ab.get("abuse_confidence", 0))
        w = WEIGHT["abuseipdb"]
        total += ac * w
        max_total += 100 * w
        details["AbuseIPDB"] = {"abuse_confidence": ac}

    # ---------------------------
    # GreyNoise
    # ---------------------------
    gn = _find(results, "GreyNoise")
    if gn and gn.get("classification"):
        cls = gn.get("classification")
        if cls == "malicious": gn_score = 100
        elif cls == "suspicious": gn_score = 70
        elif cls == "scanner": gn_score = 40
        else: gn_score = 0

        w = WEIGHT["greynoise"]
        total += gn_score * w
        max_total += 100 * w

        details["GreyNoise"] = {"classification": cls, "score": gn_score}

    # ---------------------------
    # OTX
    # ---------------------------
    otx = _find(results, "OTX")
    if otx and otx.get("pulses") is not None:
        pulse_count = otx.get("pulses")
        otx_score = 100 if pulse_count > 0 else 0

        w = WEIGHT["otx"]
        total += otx_score * w
        max_total += 100 * w

        details["OTX"] = {"pulses": pulse_count, "score": otx_score}

    # ---------------------------
    # URLhaus
    # ---------------------------
    uh = _find(results, "URLhaus")
    if uh and uh.get("query_status"):
        query = uh["query_status"]
        uh_score = 100 if query == "ok" else 0

        w = WEIGHT["urlhaus"]
        total += uh_score * w
        max_total += 100 * w

        details["URLhaus"] = {"query_status": query, "score": uh_score}

    # ---------------------------
    # IPQS
    # ---------------------------
    iq = _find(results, "IPQS")
    if iq and iq.get("fraud_score") is not None:
        fraud = float(iq.get("fraud_score", 0))
        w = WEIGHT["ipqs"]
        total += fraud * w
        max_total += 100 * w
        details["IPQS"] = {"fraud_score": fraud}

    # ---------------------------
    # Final score
    # ---------------------------
    final_pct = (total / max_total * 100) if max_total else 0
    final_pct = round(final_pct, 2)

    if final_pct >= 70:
        sev = "malicious"
    elif final_pct >= 30:
        sev = "suspicious"
    else:
        sev = "clean"

    return {
        "score": final_pct,
        "severity": sev,
        "details": details,
        "generated_at": str(datetime.utcnow())
    }
