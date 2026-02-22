import pytest
from src.ingestion.cisa import CISAKEVIngestor
from src.ingestion.abuse_ipdb import AbuseIPDBIngestor
from src.ingestion.epss import EPSSIngestor

def test_cisa_kev_ingestor_success(requests_mock):
    ingestor = CISAKEVIngestor()
    requests_mock.get(
        ingestor.url,
        json={
            "vulnerabilities": [
                {
                    "cveID": "CVE-2023-1234",
                    "vendorProject": "Vendor",
                    "product": "Product",
                    "vulnerabilityName": "Vuln Name",
                    "dateAdded": "2023-01-01T00:00:00Z",
                    "shortDescription": "Desc",
                    "requiredAction": "Action",
                    "dueDate": "2023-01-15T00:00:00Z",
                    "knownRansomwareCampaignUse": "Unknown"
                }
            ]
        }
    )
    results = ingestor.fetch_vulnerabilities()
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2023-1234"

def test_abuse_ipdb_ingestor_success(requests_mock):
    ingestor = AbuseIPDBIngestor(api_key="test_key")
    requests_mock.get(
        ingestor.base_url,
        json={
            "data": {
                "ipAddress": "1.2.3.4",
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 100,
                "countryCode": "US",
                "usageType": "Data Center",
                "isp": "ISP Name",
                "domain": "example.com",
                "totalReports": 50,
                "lastReportedAt": "2023-10-01T12:00:00+00:00"
            }
        }
    )
    result = ingestor.check_ip("1.2.3.4")
    assert result is not None
    assert result.ip_address == "1.2.3.4"
    assert result.abuse_confidence_score == 100

def test_epss_ingestor_success(requests_mock):
    ingestor = EPSSIngestor()
    requests_mock.get(
        ingestor.url,
        json={
            "data": [
                {
                    "cve": "CVE-2023-1234",
                    "epss": "0.95",
                    "percentile": "0.99"
                }
            ]
        }
    )
    # The current implementation of EPSSModel in models.py uses cve_id, 
    # but the API response uses 'cve'. Let's check the models.py again.
    # Ah, I see in epss.py: epss_data.append(EPSSModel(**data))
    # If the API returns 'cve' and the model expects 'cve_id', it might fail 
    # unless there is an alias or mapping.
    
    # Wait, I noticed a bug in epss.py:
    # logger.info(f"Successfully fetched {len(epss_data)} vulnerabilities from CISA.")
    # It says CISA instead of EPSS.

    results = ingestor.fetch_epss_data(["CVE-2023-1234"])
    # If this fails, I'll need to fix the model or the ingestor.
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2023-1234"
