CTI Dashboard

A lightweight Cyber Threat Intelligence Dashboard built using Flask, TinyDB, and real-time enrichment from APIs like VirusTotal, AbuseIPDB, GreyNoise, OTX, IPQS, URLScan, and URLhaus.

The dashboard allows you to:

Lookup IOCs (IP / Domain / URL / Hash)

Get live threat intelligence

Compute severity & risk score

Generate tags

Store results locally

View everything in a clean dashboard UI

No external database required — everything runs locally using TinyDB.

🚀 Features

🔍 IOC Lookup (IP, domain, URL, hash)

📡 Live enrichment using 7+ threat-intel providers

🧠 Automatic scoring (clean / suspicious / malicious)

🏷️ Tag generation (vt-malicious, abuse-high, etc.)

🗂️ Local persistence using TinyDB (ctidb.json)

📊 Dashboard with Chart.js doughnut chart

🔌 REST API endpoint: /api/iocs

💾 Lookup log stored in data/lookups_live.json

📁 Project Structure
CTI-DASHBOARD/
│
├── app.py                  # Flask routes
├── config.py               # Loads API keys from .env
├── models.py               # TinyDB wrapper for iocs + lookups
├── tasks.py                # Main enrichment logic
│
├── Utils/
│   ├── enrich_providers.py # Provider APIs (VT, AbuseIPDB, etc.)
│   └── enrichment.py       # Score + severity
│
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── index.html
│   └── lookup.html
│
├── data/
│   └── lookups_live.json   # Stored lookups (auto-created)
│
├── ctidb.json              # TinyDB local database
├── requirements.txt
└── README.md

🔧 Installation
1️⃣ Install dependencies
pip install -r requirements.txt

🔑 Getting API Keys & Where to Put Them

This project supports 7 different threat-intel providers.
You can use none, some, or all — the app will still run.

Create a file named .env in the root folder and add keys like this:

SECRET_KEY=change-this

VIRUSTOTAL_API_KEY=your_vt_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
GRAYNOISE_API_KEY=your_greynoise_key_here
OTX_API_KEY=your_otx_key_here
IPQS_API_KEY=your_ipqs_key_here
URLSCAN_API_KEY=your_urlscan_key_here


If a key is missing, that provider returns "no_api_key" safely.

How to get each API key
🟦 VirusTotal

Go to: https://www.virustotal.com/gui/my-apikey

Sign up → Free

Copy API Key → paste into .env as:

VIRUSTOTAL_API_KEY=xxxxx

🟥 AbuseIPDB

Create an account at: https://www.abuseipdb.com/account/api

Copy “API v2 Key” → paste into .env:

ABUSEIPDB_API_KEY=xxxxx

🟩 GreyNoise

Free community API key: https://viz.greynoise.io/signup

Paste into .env:

GRAYNOISE_API_KEY=xxxxx

🟧 OTX (AlienVault)

Create account: https://otx.alienvault.com

Go to: Settings → API Key

Paste into .env:

OTX_API_KEY=xxxxx

🟪 IPQualityScore (IPQS)

Sign up: https://www.ipqualityscore.com

Get IP Reputation API Key

Paste into .env:

IPQS_API_KEY=xxxxx

🟨 URLScan

Login at https://urlscan.io

Go to “Search” → “API Keys”

Paste:

URLSCAN_API_KEY=xxxxx

▶️ Run the App
Windows PowerShell
$env:FLASK_APP="app.py"
flask run


or simply:

python app.py

Linux / macOS
export FLASK_APP=app.py
flask run


App runs at:

http://127.0.0.1:5000/