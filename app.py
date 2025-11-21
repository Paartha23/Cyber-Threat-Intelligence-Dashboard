# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from config import Config
from models import iocs as models_iocs, lookups as models_lookups, create_ioc, upsert_ioc
from tasks import enrich_ioc
from datetime import datetime
from pymongo import MongoClient
import uuid
import logging

# Basic logging to console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cti-dashboard")

app = Flask(__name__)
app.config.from_object(Config)

iocs = models_iocs
lookups = models_lookups




# ----- Dashboard -----
@app.route("/dashboard")
def dashboard():
    # total count
    try:
        total = iocs.count_documents({})
    except:
        total = len(list(iocs.find()))

    # malicious count
    try:
        malicious = iocs.count_documents({"is_malicious": True})
    except:
        malicious = sum(1 for i in iocs.find() if i.get("is_malicious"))

    # get all recent IOCs
    try:
        recent = list(iocs.find().sort("last_seen", -1).limit(10))
    except:
        recent = sorted(list(iocs.find()),
                        key=lambda x: x.get("last_seen"),
                        reverse=True)[:10]

    # ⭐ NORMALIZE THE FIELD NAMES SO TEMPLATE CAN READ THEM
    for r in recent:
        # fix missing ioc_type
        if "ioc_type" not in r:
            r["ioc_type"] = r.get("type") or r.get("ioc_type") or "unknown"

        # ensure missing severity defaults
        if "severity" not in r:
            r["severity"] = r.get("severity", "clean")

        # ensure missing is_malicious defaults
        if "is_malicious" not in r:
            r["is_malicious"] = False

        # ensure missing score defaults
        if "score" not in r:
            r["score"] = 0

    return render_template("dashboard.html",
                           total=total,
                           malicious=malicious,
                           recent=recent)


# ----- Home / Index -----
@app.route("/")
def index():
    total = iocs.count_documents({})
    malicious = iocs.count_documents({"tags": "malicious"})
    recent_raw = list(iocs.find().sort("last_seen", -1).limit(10))
    recent = []

    for d in recent_raw:
        doc_id = str(d.get("_id"))
        value = d.get("value")
        if value and isinstance(value, str):
            lookup_doc = lookups.find_one({"_id": value})
            if lookup_doc and lookup_doc.get("value"):
                value = lookup_doc.get("value")
        tags = d.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        last_seen = d.get("last_seen")
        if last_seen:
            try:
                last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                last_seen_str = str(last_seen)
        else:
            last_seen_str = "—"

        recent.append({
            "_id": doc_id,
            "ioc_type": d.get("ioc_type"),
            "value": value,
            "tags": tags,
            "last_seen": last_seen_str
        })

    return render_template("index.html", total=total, malicious=malicious, recent=recent)


# ----- Lookup -----
@app.route("/lookup", methods=["GET", "POST"])
def lookup_page():
    if request.method == "POST":
        ioc_type = request.form.get("ioc_type")
        value = request.form.get("value", "").strip()

        if not value:
            flash("Value is required.")
            return redirect(url_for("lookup_page"))

        lookup_id = str(uuid.uuid4())

        # Save lookup FIRST
        lookups.insert_one({
            "_id": lookup_id,
            "ioc_type": ioc_type,
            "value": value,
            "status": "queued",
            "created_at": datetime.utcnow()
        })

        # Run enrichment
        try:
            enrich_ioc(lookup_id, ioc_type, value)
            flash(f"Lookup completed for {value}")
        except Exception as e:
            flash(f"Lookup failed: {e}")

        return redirect(url_for("lookup_page"))

    return render_template("lookup.html")


# ----- API -----
@app.route("/api/iocs")
def api_iocs():
    docs = list(iocs.find().sort("last_seen", -1).limit(200))
    for d in docs:
        d["_id"] = str(d["_id"])
        if isinstance(d.get("last_seen"), datetime):
            d["last_seen"] = d["last_seen"].isoformat()
    return jsonify(docs)


if __name__ == "__main__":
    logger.info("Starting CTI Dashboard app on 0.0.0.0:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
