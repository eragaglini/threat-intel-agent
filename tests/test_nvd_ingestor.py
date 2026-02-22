import pytest
from src.ingestion.nvd import NVDIngestor

@pytest.fixture
def nvd_ingestor():
    return NVDIngestor(api_key="test_key")

def test_extract_cvss_score_priorities(nvd_ingestor):
    # Test case: Multiple versions available, should pick 4.0
    metrics = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 9.8}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
    }
    assert nvd_ingestor._extract_cvss_score(metrics) == 9.8

def test_extract_cvss_score_fallback_v2(nvd_ingestor):
    # Test case: Only v2 available
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 4.2}}]
    }
    assert nvd_ingestor._extract_cvss_score(metrics) == 4.2

def test_extract_cvss_score_none(nvd_ingestor):
    # Test case: No metrics available
    assert nvd_ingestor._extract_cvss_score({}) is None

def test_fetch_recent_cves_pagination(nvd_ingestor, requests_mock, monkeypatch):
    # Force a small MAX_PER_PAGE to trigger pagination in the test
    monkeypatch.setattr(nvd_ingestor, "MAX_PER_PAGE", 2)
    
    # Mocking NVD API for two pages of size 2
    # Page 1
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2&startIndex=0",
        json={
            "totalResults": 4,
            "vulnerabilities": [
                {"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "Desc 1"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}},
                {"cve": {"id": "CVE-2", "descriptions": [{"lang": "en", "value": "Desc 2"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}}
            ]
        }
    )
    # Page 2
    requests_mock.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2&startIndex=2",
        json={
            "totalResults": 4,
            "vulnerabilities": [
                {"cve": {"id": "CVE-3", "descriptions": [{"lang": "en", "value": "Desc 3"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}},
                {"cve": {"id": "CVE-4", "descriptions": [{"lang": "en", "value": "Desc 4"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}}
            ]
        }
    )

    results = nvd_ingestor.fetch_recent_cves(limit=4)
    
    assert len(results) == 4
    assert results[0].id == "CVE-1"
    assert results[3].id == "CVE-4"
    # Ensure 2 separate API calls were made
    assert requests_mock.call_count == 2
