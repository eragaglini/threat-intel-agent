import pytest
import os
import sqlite3
from layer1.database.database import DatabaseManager
from layer1.ingestion.models import CVEModel, KEVModel
from datetime import datetime

@pytest.fixture
def db_manager(tmp_path):
    db_file = tmp_path / "test_threat_intel.db"
    return DatabaseManager(db_path=str(db_file))

def test_db_initialization(db_manager):
    assert os.path.exists(db_manager.db_path)
    with db_manager._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nvd_cves'")
        assert cursor.fetchone() is not None

def test_save_and_get_cve(db_manager):
    cve = CVEModel(
        id="CVE-2024-0001",
        description="Test CVE",
        published=datetime.now(),
        last_modified=datetime.now(),
        cvss_score=8.5,
        references=["https://example.com"]
    )
    db_manager.save_cve(cve)
    
    results = db_manager.get_recent_cves(limit=1)
    assert len(results) == 1
    assert results[0]["id"] == "CVE-2024-0001"
    assert results[0]["cvss_score"] == 8.5

def test_upsert_logic_prevents_downgrade(db_manager):
    # Initial save
    cve_v1 = CVEModel(
        id="CVE-2024-9999",
        description="V1",
        published=datetime(2024, 1, 1),
        last_modified=datetime(2024, 1, 10),
        cvss_score=5.0
    )
    db_manager.save_cve(cve_v1)
    
    # Attempt to update with an older last_modified date
    cve_v0 = CVEModel(
        id="CVE-2024-9999",
        description="V0",
        published=datetime(2024, 1, 1),
        last_modified=datetime(2024, 1, 5), # Older than v1
        cvss_score=9.9
    )
    db_manager.save_cve(cve_v0)
    
    # Should still have V1 data because of the WHERE clause in UPSERT
    results = db_manager.get_recent_cves(limit=1)
    assert results[0]["cvss_score"] == 5.0
    assert results[0]["description"] == "V1"

def test_get_critical_exploited_cves(db_manager):
    # Save a CVE in NVD
    cve = CVEModel(
        id="CVE-JOIN-1",
        description="Critical",
        published=datetime.now(),
        last_modified=datetime.now(),
        cvss_score=9.0
    )
    db_manager.save_cve(cve)
    
    # Save same CVE in CISA KEV
    kev = KEVModel(
        cveID="CVE-JOIN-1",
        vendorProject="Vendor",
        product="Product",
        vulnerabilityName="Exploited Vuln",
        dateAdded=datetime.now(),
        shortDescription="Desc",
        requiredAction="Action",
        dueDate=datetime.now(),
        knownRansomwareCampaignUse="Yes"
    )
    db_manager.save_kev(kev)
    
    critical = db_manager.get_critical_exploited_cves(min_cvss=8.0)
    assert len(critical) == 1
    assert critical[0]["id"] == "CVE-JOIN-1"
    assert critical[0]["vulnerability_name"] == "Exploited Vuln"

def test_save_ip_reputation_with_reports(db_manager):
    from layer1.ingestion.models import IPReputationModel, ReportModel
    
    report = ReportModel(
        reportedAt=datetime.now(),
        comment="Attacco SSH",
        categories=[18, 22],
        reporterId=123,
        reporterCountryCode="IT"
    )
    
    reputation = IPReputationModel(
        ipAddress="1.1.1.1",
        isPublic=True,
        ipVersion=4,
        abuseConfidenceScore=100,
        totalReports=1,
        lastReportedAt=datetime.now(),
        reports=[report]
    )
    
    db_manager.save_ip_reputation(reputation)
    
    with db_manager._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT reports_json FROM ip_reputation WHERE ip_address = '1.1.1.1'")
        row = cursor.fetchone()
        assert row is not None
        assert "Attacco SSH" in row[0]
