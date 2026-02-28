from typing import List, Optional
from layer1.utils.http_client import HTTPClient
from layer1.ingestion.models import EPSSModel
import logging

logger = logging.getLogger(__name__)


class EPSSIngestor:
    def __init__(self):
        self.url = "https://api.first.org/data/v1/epss"
        self.client = HTTPClient(base_url=self.url)

    def fetch_epss_data(self, cve_ids: List[str]) -> List[EPSSModel]:
        all_epss = []
        batch_size = 100
        
        # Dividi in chunk da 100
        for i in range(0, len(cve_ids), batch_size):
            batch = cve_ids[i:i + batch_size]
            logger.info(f"Fetching EPSS for batch {i//batch_size + 1} ({len(batch)} CVEs)...")
            
            response = self.client.get(
                endpoint="",
                params={"cve_id": ",".join(batch)}
            )
            
            if not response or "data" not in response:
                logger.warning(f"No data for batch {i//batch_size + 1}")
                continue
                
            for entry in response["data"]:
                try:
                    all_epss.append(EPSSModel(**entry))
                except (ValueError, KeyError, TypeError) as e:
                    logger.warning(f"Failed to parse EPSS entry {entry.get('cve', 'unknown')}: {e}")
                    continue
        
        logger.info(f"Successfully fetched {len(all_epss)} EPSS scores.")
        return all_epss
