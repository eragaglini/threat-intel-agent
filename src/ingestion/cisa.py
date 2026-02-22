from typing import List, Optional
from src.utils.http_client import HTTPClient
from src.ingestion.models import KEVModel
import logging

logger = logging.getLogger(__name__)

class CISAKEVIngestor:
    def __init__(self):
        self.url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        self.client = HTTPClient(base_url=self.url)

    def fetch_vulnerabilities(self) -> List[KEVModel]:
        logger.info("Fetching CISA KEV data...")
        data = self.client.get(endpoint="")
        if not data or "vulnerabilities" not in data:
            logger.error("Failed to fetch CISA KEV data.")
            return []
        
        logger.info(f"Raw response contains {len(data['vulnerabilities'])} entries")
        
        vulnerabilities = []
        for v_data in data["vulnerabilities"]:
            try:
                vulnerabilities.append(KEVModel(**v_data))
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(f"Failed to parse KEV data for {v_data.get('cveID', 'unknown')}: {e}")
                continue
        
        logger.info(f"Successfully fetched {len(vulnerabilities)} vulnerabilities from CISA.")
        return vulnerabilities
