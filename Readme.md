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

##  Features

-  **IOC Lookup** (IP, domain, URL, hash)  
-  **Real-time enrichment** using 7+ threat-intel providers  
-  **Automatic scoring** → clean / suspicious / malicious  
-  **Tag generation** (vt-malicious, abuse-high, grey-scan, etc.)  
-  **Local persistence** using TinyDB (`ctidb.json`)  
-  **Dashboard** with Chart.js doughnut graph  
-  **REST API** endpoint → `/api/iocs`  
-  Lookup logs stored at `data/lookups_live.json`  

---
##  Tech

- **Python 3**
- **Flask** (backend web framework)
- **TinyDB** (local JSON database — no MongoDB required)
- **HTML / CSS / JavaScript**
- **Bulma CSS Framework** (UI styling)
- **Chart.js** (dashboard visualizations)
- **Requests** (API calls to VT, OTX, AbuseIPDB, etc.)
- **python-dotenv** (reads `.env` API keys)

---

#  Functionality

- `app.py` → Flask routes (Home, Lookup, Dashboard, API)
- `tasks.py` → Main IOC enrichment logic  
- `models.py` → TinyDB wrapper for IOCs and lookups  
- `Utils/enrich_providers.py` → Calls VirusTotal, AbuseIPDB, OTX, GreyNoise, IPQS, URLScan, URLhaus  
- `Utils/enrichment.py` → Computes scoring + severity + risk  
- `ctidb.json` → Local IOC database  
- `data/lookups_live.json` → Stores lookup history  
- Templates:
  - `index.html`
  - `dashboard.html`
  - `lookup.html`
  - `base.html`

All results are stored locally — **no external DB required**.

---

#  How to Run the Project

Make sure Python 3 is installed.

```bash
# Clone your repository
git clone https://github.com/Paartha23/Cyber-Threat-Intelligence-Dashboard.git
cd Cyber-Threat-Intelligence-Dashboard

# Install required Python packages
pip install -r requirements.txt

# Run the Flask application
python app.py




