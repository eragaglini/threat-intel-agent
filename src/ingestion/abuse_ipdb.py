import os
import logging
from typing import Optional
from src.utils.http_client import HTTPClient
from src.ingestion.models import IPReputationModel
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class AbuseIPDBIngestor:
    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://api.abuseipdb.com/api/v2/check"
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        } if self.api_key else {"Accept": "application/json"}
        self.client = HTTPClient(base_url=self.base_url, headers=headers)

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Optional[IPReputationModel]:
        if not self.api_key:
            logger.error("AbuseIPDB API key not found. Please set ABUSEIPDB_API_KEY in .env.")
            return None
        
        logger.info(f"Checking IP reputation for {ip_address} in AbuseIPDB...")
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": max_age_days
        }
        data = self.client.get(endpoint="", params=params)
        
        if not data or "data" not in data:
            logger.error(f"Failed to check IP reputation for {ip_address}.")
            return None
        
        try:
            return IPReputationModel(**data["data"])
        except Exception as e:
            logger.warning(f"Failed to parse AbuseIPDB data for {ip_address}: {e}")
            return None
