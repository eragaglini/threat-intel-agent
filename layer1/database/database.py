import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from layer1.ingestion.models import CVEModel, KEVModel, IPReputationModel, EPSSModel

logger = logging.getLogger(__name__)


class DatabaseManager:
    def __init__(self, db_path: str = "threat_intel.db"):
        # Risolvi sempre in path assoluto al momento della costruzione
        # Questo garantisce che tutte le connessioni usino lo stesso file
        # indipendentemente dalla working directory
        if not os.path.isabs(db_path):
            db_path = os.path.join(os.getcwd(), db_path)
        
        self.db_path = db_path
        logger.info(f"DatabaseManager inizializzato con path: {self.db_path}")
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nvd_cves (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    published TEXT,
                    last_modified TEXT,
                    cvss_score REAL,
                    references_json TEXT,
                    fetched_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cisa_kev (
                    cve_id TEXT PRIMARY KEY,
                    vendor_project TEXT,
                    product TEXT,
                    vulnerability_name TEXT,
                    date_added TEXT,
                    short_description TEXT,
                    required_action TEXT,
                    due_date TEXT,
                    known_ransomware_campaign_use TEXT,
                    fetched_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address TEXT PRIMARY KEY,
                    is_public INTEGER,
                    ip_version INTEGER,
                    is_whitelisted INTEGER,
                    abuse_confidence_score INTEGER,
                    country_code TEXT,
                    usage_type TEXT,
                    isp TEXT,
                    domain TEXT,
                    total_reports INTEGER,
                    last_reported_at TEXT,
                    reports_json TEXT,
                    fetched_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS epss_scores (
                    cve_id TEXT PRIMARY KEY,
                    epss_score REAL,
                    epss_percentile REAL,
                    fetched_at TEXT DEFAULT (datetime('now'))
                )
            """)

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_nvd_published_cvss "
                "ON nvd_cves(published, cvss_score)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_cisa_date_added "
                "ON cisa_kev(date_added)"
            )

            self._migrate_schema(cursor)
            conn.commit()

    def _migrate_schema(self, cursor):
        """Simple migration to add missing columns to existing tables."""
        tables = ["nvd_cves", "cisa_kev", "ip_reputation"]
        for table in tables:
            cursor.execute(f"PRAGMA table_info({table})")
            columns = [info[1] for info in cursor.fetchall()]
            if "fetched_at" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} "
                    f"ADD COLUMN fetched_at TEXT DEFAULT CURRENT_TIMESTAMP"
                )
            if "updated_at" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} "
                    f"ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP"
                )
            if table == "ip_reputation" and "reports_json" not in columns:
                cursor.execute(
                    "ALTER TABLE ip_reputation ADD COLUMN reports_json TEXT"
                )

    def save_cve(self, cve: CVEModel):
        self.save_multiple_cves([cve])

    def save_kev(self, kev: KEVModel):
        self.save_multiple_kev([kev])

    def save_ip_reputation(self, reputation: IPReputationModel):
        self.save_multiple_ip_reputation([reputation])

    def save_multiple_cves(self, cves: List[CVEModel]):
        data = [
            (
                cve.id,
                cve.description,
                cve.published.isoformat()
                if isinstance(cve.published, datetime)
                else cve.published,
                cve.last_modified.isoformat()
                if isinstance(cve.last_modified, datetime)
                else cve.last_modified,
                cve.cvss_score,
                json.dumps([str(r) for r in cve.references]),
            )
            for cve in cves
        ]
        query = """
            INSERT INTO nvd_cves (
                id, description, published, last_modified,
                cvss_score, references_json, fetched_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(id) DO UPDATE SET
                description = excluded.description,
                cvss_score = excluded.cvss_score,
                last_modified = excluded.last_modified,
                references_json = excluded.references_json,
                updated_at = datetime('now')
            WHERE excluded.last_modified > nvd_cves.last_modified
        """
        with self._get_connection() as conn:
            conn.executemany(query, data)

    def save_multiple_kev(self, kevs: List[KEVModel]):
        data = [
            (
                kev.cve_id,
                kev.vendor_project,
                kev.product,
                kev.vulnerability_name,
                kev.date_added.isoformat()
                if isinstance(kev.date_added, datetime)
                else kev.date_added,
                kev.short_description,
                kev.required_action,
                kev.due_date.isoformat()
                if isinstance(kev.due_date, datetime)
                else kev.due_date,
                kev.known_ransomware_campaign_use,
            )
            for kev in kevs
        ]
        query = """
            INSERT INTO cisa_kev (
                cve_id, vendor_project, product, vulnerability_name,
                date_added, short_description, required_action, due_date,
                known_ransomware_campaign_use, fetched_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(cve_id) DO UPDATE SET
                vulnerability_name = excluded.vulnerability_name,
                short_description = excluded.short_description,
                required_action = excluded.required_action,
                updated_at = datetime('now')
            WHERE excluded.vulnerability_name != cisa_kev.vulnerability_name
               OR excluded.short_description != cisa_kev.short_description
        """
        with self._get_connection() as conn:
            conn.executemany(query, data)

    def save_multiple_ip_reputation(self, reputations: List[IPReputationModel]):
        data = [
            (
                rep.ip_address,
                1 if rep.is_public else 0,
                rep.ip_version,
                1 if rep.is_whitelisted else 0,
                rep.abuse_confidence_score,
                rep.country_code,
                rep.usage_type,
                rep.isp,
                rep.domain,
                rep.total_reports,
                rep.last_reported_at.isoformat() if rep.last_reported_at else None,
                json.dumps([
                    json.loads(r.model_dump_json(by_alias=True))
                    for r in rep.reports
                ]) if rep.reports else None,
            )
            for rep in reputations
        ]
        query = """
            INSERT INTO ip_reputation (
                ip_address, is_public, ip_version, is_whitelisted,
                abuse_confidence_score, country_code, usage_type, isp,
                domain, total_reports, last_reported_at, reports_json,
                fetched_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(ip_address) DO UPDATE SET
                abuse_confidence_score = excluded.abuse_confidence_score,
                total_reports = excluded.total_reports,
                last_reported_at = excluded.last_reported_at,
                reports_json = excluded.reports_json,
                updated_at = datetime('now')
            WHERE excluded.last_reported_at > ip_reputation.last_reported_at
               OR excluded.abuse_confidence_score != ip_reputation.abuse_confidence_score
        """
        with self._get_connection() as conn:
            conn.executemany(query, data)

    def get_recent_cves(self, limit: int = 10) -> List[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM nvd_cves ORDER BY published DESC LIMIT ?",
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_kev_by_cve(self, cve_id: str) -> Optional[dict]:
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cisa_kev WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_critical_exploited_cves(
        self, min_cvss: float = 7.0, limit: int = 50
    ) -> List[dict]:
        """
        Recupera CVE critiche con dati KEV e EPSS joinati.
        LEFT JOIN su epss_scores: include CVE anche senza score EPSS.
        Ordina per EPSS score decrescente, poi CVSS, poi data KEV.
        """
        query = """
            SELECT
                n.id,
                n.cvss_score,
                n.description,
                n.published,
                n.last_modified,
                k.vulnerability_name,
                k.known_ransomware_campaign_use,
                k.date_added,
                e.epss_score,
                e.epss_percentile
            FROM nvd_cves n
            JOIN cisa_kev k ON n.id = k.cve_id
            LEFT JOIN epss_scores e ON n.id = e.cve_id
            WHERE n.cvss_score >= ?
            ORDER BY
                COALESCE(e.epss_score, 0) DESC,
                n.cvss_score DESC,
                k.date_added DESC
            LIMIT ?
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (min_cvss, limit))
            return [dict(row) for row in cursor.fetchall()]

    def save_multiple_epss(self, epss_list: List[EPSSModel]):
        if not epss_list:
            logger.warning("save_multiple_epss chiamata con lista vuota.")
            return

        data = []
        for e in epss_list:
            try:
                fetched_at = (
                    e.fetched_at.isoformat()
                    if isinstance(e.fetched_at, datetime)
                    else datetime.now().isoformat()
                )
                data.append((
                    e.cve_id,
                    float(e.epss_score),
                    float(e.epss_percentile),
                    fetched_at
                ))
            except Exception as ex:
                logger.warning(
                    f"Skipping EPSS record {getattr(e, 'cve_id', '?')}: {ex}"
                )

        if not data:
            logger.error("Nessun record EPSS valido dopo la validazione.")
            return

        query = """
            INSERT INTO epss_scores (
                cve_id, epss_score, epss_percentile, fetched_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss_score = excluded.epss_score,
                epss_percentile = excluded.epss_percentile,
                fetched_at = excluded.fetched_at
        """

        # Processa in batch da 500 per evitare limiti SQLite
        batch_size = 500
        total_saved = 0

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA foreign_keys = OFF")
            
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                conn.executemany(query, batch)
                total_saved += len(batch)
                logger.debug(
                    f"Batch {i//batch_size + 1}: "
                    f"inseriti {len(batch)} record "
                    f"(totale: {total_saved}/{len(data)})"
                )

            conn.commit()
            logger.info(f"Committed {total_saved} EPSS records to DB.")

        except Exception as ex:
            conn.rollback()
            logger.error(f"Database error in save_multiple_epss: {ex}")
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------ #
    #  NUOVO METODO — sincronizzazione incrementale EPSS                  #
    # ------------------------------------------------------------------ #

    def get_cves_without_epss(self) -> List[dict]:
        """
        Restituisce tutte le CVE che non hanno ancora un record EPSS.
        Usato da layer1/main.py per sincronizzazione incrementale:
        fetcha EPSS solo per CVE non ancora coperte, evitando
        re-fetch inutili di dati già presenti.
        """
        query = """
            SELECT n.id
            FROM nvd_cves n
            LEFT JOIN epss_scores e ON n.id = e.cve_id
            WHERE e.cve_id IS NULL
            ORDER BY n.published DESC
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------ #
    #  NUOVO METODO — statistiche copertura EPSS                          #
    # ------------------------------------------------------------------ #

    def get_epss_coverage_stats(self) -> Dict[str, int]:
        query = """
            SELECT
                COUNT(n.id)               AS total_cves,
                COUNT(e.cve_id)           AS cves_with_epss,
                COUNT(n.id) - COUNT(e.cve_id) AS cves_without_epss
            FROM nvd_cves n
            LEFT JOIN epss_scores e ON n.id = e.cve_id
        """
        with self._get_connection() as conn:
            conn.execute("PRAGMA wal_checkpoint(FULL)")   # ← forza flush WAL
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            return dict(cursor.fetchone())