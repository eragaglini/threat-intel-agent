from typing import List, Optional
from src.utils.http_client import HTTPClient
from src.ingestion.models import EPSSModel
import logging

logger = logging.getLogger(__name__)


class EPSSIngestor:
    def __init__(self):
        self.url = "https://api.first.org/data/v1/epss"
        self.client = HTTPClient(base_url=self.url)

    def fetch_epss_data(self, cve_ids: List[str]) -> List[EPSSModel]:
        logger.info("Fetching EPSS data...")
        epss_json_response = self.client.get(
            endpoint="", params={"cve_id": ",".join(cve_ids)}
        )

        if "data" not in epss_json_response:
            logger.error("Failed to fetch EPSS data.")
            return []

        logger.info(f"Raw response contains {len(epss_json_response['data'])} entries")

        epss_data = []
        for data in epss_json_response["data"]:
            try:
                epss_data.append(EPSSModel(**data))
            except (ValueError, KeyError, TypeError) as e:
                logger.warning(
                    f"Failed to parse EPSS data for {data.get('cve', 'unknown')}: {e}"
                )
                continue

        logger.info(f"Successfully fetched {len(epss_data)} vulnerabilities from EPSS.")
        return epss_data
