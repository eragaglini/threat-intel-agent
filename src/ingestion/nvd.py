import os
import logging
from typing import List, Optional, Dict, Any
from src.utils.http_client import HTTPClient
from src.ingestion.models import CVEModel
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

class NVDIngestor:
    MAX_PER_PAGE = 2000

    def __init__(self, api_key: Optional[str] = None):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        self.client = HTTPClient(base_url=self.base_url, headers=headers)

    def _extract_cvss_score(self, metrics: dict) -> Optional[float]:
        """
        Extracts the best available CVSS score from the metrics dictionary.
        Prioritizes newer versions: 4.0 > 3.1 > 3.0 > 2.0.
        """
        versions = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
        for version in versions:
            metric_list = metrics.get(version, [])
            if metric_list:
                # We take the first metric entry (usually the primary one)
                return metric_list[0].get("cvssData", {}).get("baseScore")
        return None

    def fetch_recent_cves(self, limit: int = 10, days: int = 30) -> List[CVEModel]:
        from datetime import datetime, timedelta, timezone
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        start_fmt = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_fmt = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        
        logger.info(f"Fetching CVEs from {start_fmt} to {end_fmt} (limit: {limit})...")
        
        all_cves = []
        start_index = 0
        
        while len(all_cves) < limit:
            batch_size = min(self.MAX_PER_PAGE, limit - len(all_cves))
            
            # Costruisci l'URL manualmente per evitare encoding automatico
            url = (
                f"?resultsPerPage={batch_size}"
                f"&startIndex={start_index}"
                f"&pubStartDate={start_fmt}"
                f"&pubEndDate={end_fmt}"
            )
            
            data = self.client.get(endpoint=url)  # nessun params={}

            
            if not data or "vulnerabilities" not in data:
                logger.error(f"Failed to fetch NVD data at startIndex {start_index}")
                break

            total_available = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                break

            for v_entry in vulnerabilities:
                cve_data = v_entry.get("cve", {})
                try:
                    desc_list = cve_data.get("descriptions", [])
                    description = next((d["value"] for d in desc_list if d["lang"] == "en"), "No description available.")
                    
                    # Extracting CVSS using the private helper
                    cvss_metrics = cve_data.get("metrics", {})
                    cvss_score = self._extract_cvss_score(cvss_metrics)
                    
                    ref_list = [r.get("url") for r in cve_data.get("references", [])]
                    
                    cve_model = CVEModel(
                        id=cve_data.get("id"),
                        description=description,
                        published=cve_data.get("published"),
                        last_modified=cve_data.get("lastModified"),
                        cvss_score=cvss_score,
                        references=ref_list
                    )
                    all_cves.append(cve_model)
                except Exception as e:
                    logger.warning(f"Failed to parse NVD data for {cve_data.get('id', 'unknown')}: {e}")
                    continue

            logger.info(f"Progress: {len(all_cves)}/{min(limit, total_available)} CVEs fetched.")
            
            start_index += len(vulnerabilities)
            if start_index >= total_available:
                break

        logger.info(f"Successfully fetched {len(all_cves)} CVEs from NVD.")
        return all_cves[:limit]
