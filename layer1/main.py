import logging
from layer1.ingestion.cisa import CISAKEVIngestor
from layer1.ingestion.nvd import NVDIngestor
from layer1.ingestion.abuse_ipdb import AbuseIPDBIngestor
from layer1.ingestion.epss import EPSSIngestor
from layer1.database.database import DatabaseManager
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
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
            print(
                f"CISA KEV: {v.cve_id} - {v.vulnerability_name} (Ransomware Use: {v.known_ransomware_campaign_use})"
            )

    print("-" * 50)

    # 2. NVD CVEs - Fetch more to see if they are in CISA KEV
    nvd_ingestor = NVDIngestor()
    nvd_cves = nvd_ingestor.fetch_recent_cves(
        limit=2000, days=120  # 2 anni
    )
    if nvd_cves:
        logger.info(f"Saving {len(nvd_cves)} NVD CVEs to DB...")
        db_manager.save_multiple_cves(nvd_cves)
        # Show first 5
        for cve in nvd_cves[:5]:
            print(
                f"NVD CVE: {cve.id} - CVSS: {cve.cvss_score} - Published: {cve.published}"
            )

    print("-" * 50)

    # 3. AbuseIPDB - Fetching the actual BLACKLIST of malicious IPs
    abuse_ingestor = AbuseIPDBIngestor()
    logger.info("Fetching real-time blacklist from AbuseIPDB...")
    blacklist = abuse_ingestor.fetch_blacklist(limit=10) # Recuperiamo i 10 peggiori ora
    if blacklist:
        logger.info(f"Saving {len(blacklist)} malicious IPs to DB...")
        db_manager.save_multiple_ip_reputation(blacklist)
        for ip in blacklist:
            print(
                f"BAD IP: {ip.ip_address} - Confidence: {ip.abuse_confidence_score}% - Reports: {ip.total_reports}"
            )
    else:
        print("AbuseIPDB blacklist fetch skipped or failed (likely missing API Key).")

    print("-" * 50)

    # 4. Testing the new JOIN functionality
    logger.info("Querying for critical and exploited vulnerabilities (JOIN)...")
    critical_exploited = db_manager.get_critical_exploited_cves(
        min_cvss=0.0
    )  # Using 0.0 because some NVD entries might not have scores in this PoC
    if critical_exploited:
        print(f"Found {len(critical_exploited)} CRITICAL EXPLOITED vulnerabilities:")
        for v in critical_exploited[:5]:
            print(f"- {v['id']} (CVSS: {v['cvss_score']}): {v['vulnerability_name']}")
    else:
        print(
            "No matches found for critical exploited vulnerabilities (check if data is loaded in both tables)."
        )

    # 5. Recupero gli EPSS, ma per prima cosa devo recuperare i cves recenti
    logger.info("Fetching EPSS data...")
    recent_cves = db_manager.get_recent_cves(limit=2000)
    # creo una lista di cves da passare all'epss
    cve_ids = [cve["id"] for cve in recent_cves]
    logger.info(f"Found {len(cve_ids)} recent cves")
    epss_ingestor = EPSSIngestor()
    epss_data = epss_ingestor.fetch_epss_data(cve_ids)
    if epss_data:
        print(f"Successfully fetched {len(epss_data)} EPSS scores.")
        db_manager.save_multiple_epss(epss_data)
    else:
        print("Failed to fetch EPSS data.")


if __name__ == "__main__":
    main()
