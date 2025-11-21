# config.py
import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/ctidb")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    GRAYNOISE_API_KEY = os.getenv("GRAYNOISE_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    IPQS_API_KEY = os.getenv("IPQS_API_KEY", "")
