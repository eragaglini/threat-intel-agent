import logging
from layer1.ingestion.cisa import CISAKEVIngestor
from layer1.ingestion.nvd import NVDIngestor
from layer1.ingestion.abuse_ipdb import AbuseIPDBIngestor
from layer1.ingestion.epss import EPSSIngestor
from layer1.database.database import DatabaseManager
from dotenv import load_dotenv

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    load_dotenv()
    logger.info("Starting Threat Intel Agent Layer 1 - Data Ingestion PoC...")

    db_manager = DatabaseManager()
    logger.info(f"Database initialized at: {db_manager.db_path}")

    # 1. CISA KEV
    try:
        cisa_ingestor = CISAKEVIngestor()
        kev_vulnerabilities = cisa_ingestor.fetch_vulnerabilities()
        if kev_vulnerabilities:
            logger.info(f"Saving {len(kev_vulnerabilities)} CISA KEV entries to DB...")
            db_manager.save_multiple_kev(kev_vulnerabilities)
            for v in kev_vulnerabilities[:3]:
                print(
                    f"CISA KEV: {v.cve_id} - {v.vulnerability_name} "
                    f"(Ransomware Use: {v.known_ransomware_campaign_use})"
                )
    except Exception as e:
        logger.warning(f"CISA KEV fetch fallito: {e}. Continuando...")

    print("-" * 50)

    # 2. NVD CVEs
    try:
        nvd_ingestor = NVDIngestor()
        nvd_cves = nvd_ingestor.fetch_recent_cves(limit=2000, days=120)
        if nvd_cves:
            logger.info(f"Saving {len(nvd_cves)} NVD CVEs to DB...")
            db_manager.save_multiple_cves(nvd_cves)
            for cve in nvd_cves[:5]:
                print(
                    f"NVD CVE: {cve.id} - CVSS: {cve.cvss_score} "
                    f"- Published: {cve.published}"
                )
    except Exception as e:
        logger.warning(f"NVD fetch fallito: {e}. Continuando...")

    print("-" * 50)

    # 3. AbuseIPDB — rate limit frequente, non blocca la pipeline
    try:
        abuse_ingestor = AbuseIPDBIngestor()
        logger.info("Fetching real-time blacklist from AbuseIPDB...")
        blacklist = abuse_ingestor.fetch_blacklist(limit=10)
        if blacklist:
            logger.info(f"Saving {len(blacklist)} malicious IPs to DB...")
            db_manager.save_multiple_ip_reputation(blacklist)
            for ip in blacklist:
                print(
                    f"BAD IP: {ip.ip_address} "
                    f"- Confidence: {ip.abuse_confidence_score}% "
                    f"- Reports: {ip.total_reports}"
                )
        else:
            print("AbuseIPDB: nessun dato ricevuto.")
    except Exception as e:
        logger.warning(
            f"AbuseIPDB fetch fallito: {e}. "
            f"Probabilmente rate limit giornaliero raggiunto. "
            f"Continuando con gli altri ingestor..."
        )
        print("AbuseIPDB skipped.")

    print("-" * 50)

    # 4. JOIN CVE + KEV
    logger.info("Querying for critical and exploited vulnerabilities (JOIN)...")
    critical_exploited = db_manager.get_critical_exploited_cves(min_cvss=0.0)
    if critical_exploited:
        print(f"Found {len(critical_exploited)} CRITICAL EXPLOITED vulnerabilities:")
        for v in critical_exploited[:5]:
            print(
                f"- {v['id']} (CVSS: {v['cvss_score']}): {v['vulnerability_name']}"
            )
    else:
        print(
            "No matches found for critical exploited vulnerabilities "
            "(check if data is loaded in both tables)."
        )

    print("-" * 50)

    # 5. EPSS — sincronizzazione incrementale
    logger.info("Fetching EPSS data for CVEs without existing scores...")
    cves_without_epss = db_manager.get_cves_without_epss()

    if not cves_without_epss:
        logger.info("All CVEs already have EPSS scores. Nothing to fetch.")
    else:
        cve_ids = [cve["id"] for cve in cves_without_epss]
        logger.info(
            f"Found {len(cve_ids)} CVEs without EPSS scores. "
            f"Fetching from FIRST.org..."
        )

        try:
            epss_ingestor = EPSSIngestor()
            epss_data = epss_ingestor.fetch_epss_data(cve_ids)

            if epss_data:
                db_manager.save_multiple_epss(epss_data)

                fetched = len(epss_data)
                missing = len(cve_ids) - fetched
                logger.info(
                    f"Saved {fetched} EPSS scores ({fetched}/{len(cve_ids)} CVEs)."
                )
                if missing > 0:
                    logger.warning(
                        f"{missing} CVEs senza record EPSS su FIRST.org "
                        f"(probabilmente troppo recenti)."
                    )
            else:
                logger.error("EPSS fetch fallito per tutti i batch.")

        except Exception as e:
            logger.warning(f"EPSS fetch fallito: {e}. Continuando...")

    # Statistiche finali
    print("-" * 50)
    stats = db_manager.get_epss_coverage_stats()
    logger.info(
        f"EPSS coverage finale: {stats['cves_with_epss']}/{stats['total_cves']} CVEs "
        f"({stats['cves_without_epss']} ancora senza score)"
    )


if __name__ == "__main__":
    main()