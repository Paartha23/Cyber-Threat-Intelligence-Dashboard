# check_config.py
from config import Config
print("VIRUSTOTAL_API_KEY:", bool(getattr(Config, "VIRUSTOTAL_API_KEY", None)))
print("ABUSEIPDB_API_KEY:", bool(getattr(Config, "ABUSEIPDB_API_KEY", None)))
print("GRAYNOISE_API_KEY:", bool(getattr(Config, "GRAYNOISE_API_KEY", None)))
print("OTX_API_KEY:", bool(getattr(Config, "OTX_API_KEY", None)))
print("IPQS_API_KEY:", bool(getattr(Config, "IPQS_API_KEY", None)))
print("URLSCAN_API_KEY:", bool(getattr(Config, "URLSCAN_API_KEY", None)))
