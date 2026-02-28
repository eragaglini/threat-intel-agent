import os
import logging
from typing import Optional
from layer1.utils.http_client import HTTPClient
from layer1.ingestion.models import IPReputationModel
from dotenv import load_dotenv
from typing import List

load_dotenv()
logger = logging.getLogger(__name__)

class AbuseIPDBIngestor:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        # Base URL changed to the root of the API
        self.base_url = "https://api.abuseipdb.com/api/v2"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        } if self.api_key else {"Accept": "application/json"}
        self.client = HTTPClient(base_url=self.base_url, headers=headers)

    def check_ip(self, ip_address: str, max_age_days: int = 90, verbose: bool = True) -> Optional[IPReputationModel]:
        if not self.api_key:
            logger.error("AbuseIPDB API key not found. Please set ABUSEIPDB_API_KEY in .env.")
            return None
        
        logger.info(f"Checking IP reputation for {ip_address} in AbuseIPDB...")
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days
        }
        if verbose:
            params["verbose"] = ""
        
        data = self.client.get(endpoint="/check", params=params)
        
        if not data or "data" not in data:
            logger.error(f"Failed to check IP reputation for {ip_address}.")
            return None
        
        try:
            return IPReputationModel(**data["data"])
        except Exception as e:
            logger.warning(f"Failed to parse AbuseIPDB data for {ip_address}: {e}")
            return None

    def fetch_blacklist(self, confidence_minimum: int = 90, limit: int = 100) -> List[IPReputationModel]:
        if not self.api_key:
            logger.error("AbuseIPDB API key not found.")
            return []

        logger.info(f"Fetching IP blacklist (min confidence: {confidence_minimum}%)...")
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit
        }
        data = self.client.get(endpoint="/blacklist", params=params)

        if not data or "data" not in data:
            logger.error("Failed to fetch blacklist.")
            return []

        ips = []
        for ip_data in data["data"]:
            try:
                # La blacklist restituisce un set di campi leggermente diverso,
                # mappiamo i minimi necessari per IPReputationModel
                ips.append(IPReputationModel(
                    ipAddress=ip_data.get("ipAddress"),
                    isPublic=True,
                    ipVersion=ip_data.get("ipVersion", 4),
                    abuseConfidenceScore=ip_data.get("abuseConfidenceScore"),
                    countryCode=ip_data.get("countryCode"),
                    totalReports=ip_data.get("totalReports", 0),
                    lastReportedAt=ip_data.get("lastReportedAt"),
                    isp=None, # Non inclusi nella blacklist base
                    domain=None,
                    usageType=None
                ))
            except Exception as e:
                logger.warning(f"Failed to parse blacklist entry: {e}")
                continue
        
        return ips
