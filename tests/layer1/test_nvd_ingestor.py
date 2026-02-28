import pytest
import re
from layer1.ingestion.nvd import NVDIngestor

@pytest.fixture
def nvd_ingestor():
    return NVDIngestor(api_key="test_key")

def test_extract_cvss_score_priorities(nvd_ingestor):
    metrics = {
        "cvssMetricV40": [{"cvssData": {"baseScore": 9.8}}],
        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]
    }
    assert nvd_ingestor._extract_cvss_score(metrics) == 9.8

def test_extract_cvss_score_fallback_v2(nvd_ingestor):
    metrics = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 4.2}}]
    }
    assert nvd_ingestor._extract_cvss_score(metrics) == 4.2

def test_extract_cvss_score_none(nvd_ingestor):
    assert nvd_ingestor._extract_cvss_score({}) is None

def test_fetch_recent_cves_pagination(nvd_ingestor, requests_mock, monkeypatch):
    # Force a small MAX_PER_PAGE to trigger pagination in the test
    monkeypatch.setattr(nvd_ingestor, "MAX_PER_PAGE", 2)
    
    # Base NVD URL pattern
    # We use regex to match the URL and ignore dynamic date parameters
    url_pattern_1 = re.compile(r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*resultsPerPage=2.*startIndex=0.*")
    url_pattern_2 = re.compile(r"https://services\.nvd\.nist\.gov/rest/json/cves/2\.0.*resultsPerPage=2.*startIndex=2.*")

    requests_mock.get(
        url_pattern_1,
        json={
            "totalResults": 4,
            "vulnerabilities": [
                {"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "Desc 1"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}},
                {"cve": {"id": "CVE-2", "descriptions": [{"lang": "en", "value": "Desc 2"}], "metrics": {}, "published": "2024-01-01T00:00:00", "lastModified": "2024-01-01T00:00:00"}}
            ]
        }
    )
    
    requests_mock.get(
        url_pattern_2,
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
    assert requests_mock.call_count == 2
