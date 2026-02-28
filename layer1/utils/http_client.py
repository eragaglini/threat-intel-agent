import requests
import logging
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Optional, Dict, Any

# Configure simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPClient:
    def __init__(self, base_url: str, headers: Optional[Dict[str, str]] = None):
        self.base_url = base_url
        self.headers = headers or {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(requests.exceptions.RequestException)
    )
    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        url = f"{self.base_url}{endpoint}" if not endpoint.startswith("http") else endpoint
        try:
            response = self.session.get(url, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning(f"Rate limit exceeded for {url}. Retrying...")
                raise # tenacity will handle retry
            logger.error(f"HTTP error occurred: {e}")
            return None
        except Exception as e:
            logger.error(f"An error occurred: {e}")
            raise # retry other transient errors
