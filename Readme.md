# CTI Dashboard

A lightweight **Cyber Threat Intelligence Dashboard** built using **Flask**, **TinyDB**, and real-time enrichment from APIs like:

- VirusTotal  
- AbuseIPDB  
- GreyNoise  
- OTX (AlienVault)  
- IPQS  
- URLScan  
- URLhaus  

This dashboard allows you to:

- Lookup IOCs (**IP / Domain / URL / Hash**)  
- Get **live threat intelligence**  
- Compute **severity & risk score**  
- Auto-generate threat **tags**  
- Store results locally  
- View everything in a clean dashboard UI  
- Run **without MongoDB** — TinyDB handles storage locally

---

## 🚀 Features

- 🔍 **IOC Lookup** (IP, domain, URL, hash)  
- 📡 **Real-time enrichment** using 7+ threat-intel providers  
- 🧠 **Automatic scoring** → clean / suspicious / malicious  
- 🏷️ **Tag generation** (vt-malicious, abuse-high, grey-scan, etc.)  
- 🗂️ **Local persistence** using TinyDB (`ctidb.json`)  
- 📊 **Dashboard** with Chart.js doughnut graph  
- 🔌 **REST API** endpoint → `/api/iocs`  
- 💾 Lookup logs stored at `data/lookups_live.json`  

---

## 📁 Project Structure
-CTI-Dashboard
│
├── app.py # Flask application routes
├── config.py # Loads API keys from .env
├── models.py # TinyDB wrapper for IOCs + lookups
├── tasks.py # Main enrichment logic
│
├── Utils/
│ ├── enrich_providers.py # Provider lookup functions (VT, AbuseIPDB...)
│ └── enrichment.py # Score + severity calculation
│
├── templates/
│ ├── base.html
│ ├── dashboard.html
│ ├── index.html
│ └── lookup.html
│
├── data/
│ └── lookups_live.json # Saved lookup entries (auto-created)
│
├── ctidb.json # TinyDB local database
├── requirements.txt
└── README.md

