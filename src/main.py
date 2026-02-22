import logging
from src.ingestion.cisa import CISAKEVIngestor
from src.ingestion.nvd import NVDIngestor
from src.ingestion.abuse_ipdb import AbuseIPDBIngestor
from src.ingestion.epss import EPSSIngestor
from src.database.database import DatabaseManager
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    load_dotenv()
    logger.info("Starting Threat Intel Agent Layer 1 - Data Ingestion PoC...")

    # Initialize Database
    db_manager = DatabaseManager()
    logger.info(f"Database initialized at: {db_manager.db_path}")

    # 1. CISA KEV - Publicly available without key
    cisa_ingestor = CISAKEVIngestor()
    kev_vulnerabilities = cisa_ingestor.fetch_vulnerabilities()
    if kev_vulnerabilities:
        logger.info(f"Saving {len(kev_vulnerabilities)} CISA KEV entries to DB...")
        db_manager.save_multiple_kev(kev_vulnerabilities)
        # Just show the first 3 for demonstration
        for v in kev_vulnerabilities[:3]:
            print(f"CISA KEV: {v.cve_id} - {v.vulnerability_name} (Ransomware Use: {v.known_ransomware_campaign_use})")
    
    print("-" * 50)

    # 2. NVD CVEs - Fetch more to see if they are in CISA KEV
    nvd_ingestor = NVDIngestor()
    nvd_cves = nvd_ingestor.fetch_recent_cves(limit=50) # Fetch 50 instead of 5
    if nvd_cves:
        logger.info(f"Saving {len(nvd_cves)} NVD CVEs to DB...")
        db_manager.save_multiple_cves(nvd_cves)
        # Show first 5
        for cve in nvd_cves[:5]:
            print(f"NVD CVE: {cve.id} - CVSS: {cve.cvss_score} - Published: {cve.published}")

    print("-" * 50)

    # 3. AbuseIPDB - Using a known active scanner IP for demonstration
    abuse_ingestor = AbuseIPDBIngestor()
    # 185.224.128.83 is often associated with SSH brute force attempts
    test_ip = "185.224.128.83" 
    logger.info(f"Testing AbuseIPDB for {test_ip} (Known scanner)")
    reputation = abuse_ingestor.check_ip(test_ip)
    if reputation:
        logger.info(f"Saving IP reputation for {test_ip} to DB...")
        db_manager.save_ip_reputation(reputation)
        print(f"IP Reputation: {reputation.ip_address} - Score: {reputation.abuse_confidence_score} - Total Reports: {reputation.total_reports}")
    else:
        print("AbuseIPDB reputation check skipped or failed (likely missing API Key).")

    print("-" * 50)
    
    # 4. Testing the new JOIN functionality
    logger.info("Querying for critical and exploited vulnerabilities (JOIN)...")
    critical_exploited = db_manager.get_critical_exploited_cves(min_cvss=0.0) # Using 0.0 because some NVD entries might not have scores in this PoC
    if critical_exploited:
        print(f"Found {len(critical_exploited)} CRITICAL EXPLOITED vulnerabilities:")
        for v in critical_exploited[:5]:
            print(f"- {v['id']} (CVSS: {v['cvss_score']}): {v['vulnerability_name']}")
    else:
        print("No matches found for critical exploited vulnerabilities (check if data is loaded in both tables).")

    # 5. Recupero gli EPSS, ma per prima cosa devo recuperare i cves recenti
    logger.info("Fetching EPSS data...")
    recent_cves = db_manager.get_recent_cves()
    # creo una lista di cves da passare all'epss
    cve_ids = [cve["id"] for cve in recent_cves]
    logger.info(f"Found {len(cve_ids)} recent cves")
    epss_ingestor = EPSSIngestor()
    epss_data = epss_ingestor.fetch_epss_data(cve_ids)
    if epss_data:
        print(f"Successfully fetched {len(epss_data)} vulnerabilities from CISA.")
        db_manager.save_multiple_epss(epss_data)
    else:
        print("Failed to fetch EPSS data.")

if __name__ == "__main__":
    main()
