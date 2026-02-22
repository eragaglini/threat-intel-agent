import sqlite3
import json
from datetime import datetime
from typing import List, Optional, Dict, Any
from src.ingestion.models import CVEModel, KEVModel, IPReputationModel, EPSSModel


class DatabaseManager:
    def __init__(self, db_path: str = "threat_intel.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Table for NVD CVEs
            cursor.execute(
                """
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
            """
            )

            # Table for CISA KEV
            cursor.execute(
                """
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
            """
            )

            # Table for IP Reputation
            cursor.execute(
                """
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
                    fetched_at TEXT DEFAULT (datetime('now')),
                    updated_at TEXT DEFAULT (datetime('now'))
                )
            """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS epss_scores (
                    cve_id TEXT PRIMARY KEY,
                    epss_score REAL,
                    epss_percentile REAL,
                    fetched_at TEXT DEFAULT (datetime('now')),
                    FOREIGN KEY (cve_id) REFERENCES nvd_cves(id)
                )
            """
            )

            # Add Indexes for performance
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_nvd_published_cvss ON nvd_cves(published, cvss_score)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_cisa_date_added ON cisa_kev(date_added)"
            )

            # Migration check: Add columns if they don't exist (for existing DBs)
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
                    f"ALTER TABLE {table} ADD COLUMN fetched_at TEXT DEFAULT CURRENT_TIMESTAMP"
                )
            if "updated_at" not in columns:
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN updated_at TEXT DEFAULT CURRENT_TIMESTAMP"
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
                (
                    cve.published.isoformat()
                    if isinstance(cve.published, datetime)
                    else cve.published
                ),
                (
                    cve.last_modified.isoformat()
                    if isinstance(cve.last_modified, datetime)
                    else cve.last_modified
                ),
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
                (
                    kev.date_added.isoformat()
                    if isinstance(kev.date_added, datetime)
                    else kev.date_added
                ),
                kev.short_description,
                kev.required_action,
                (
                    kev.due_date.isoformat()
                    if isinstance(kev.due_date, datetime)
                    else kev.due_date
                ),
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
            )
            for rep in reputations
        ]
        query = """
            INSERT INTO ip_reputation (
                ip_address, is_public, ip_version, is_whitelisted, 
                abuse_confidence_score, country_code, usage_type, isp, 
                domain, total_reports, last_reported_at, fetched_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
            ON CONFLICT(ip_address) DO UPDATE SET
                abuse_confidence_score = excluded.abuse_confidence_score,
                total_reports = excluded.total_reports,
                last_reported_at = excluded.last_reported_at,
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
                "SELECT * FROM nvd_cves ORDER BY published DESC LIMIT ?", (limit,)
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
        query = """
            SELECT 
                n.id, n.cvss_score, n.description, 
                k.vulnerability_name, k.known_ransomware_campaign_use, k.date_added
            FROM nvd_cves n
            JOIN cisa_kev k ON n.id = k.cve_id
            WHERE n.cvss_score >= ?
            ORDER BY n.cvss_score DESC, k.date_added DESC
            LIMIT ?
        """
        with self._get_connection() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, (min_cvss, limit))
            return [dict(row) for row in cursor.fetchall()]
        
    def save_multiple_epss(self, epss_list: List[EPSSModel]):
        data = [
            (
                e.cve_id,
                e.epss_score,
                e.epss_percentile,
                e.fetched_at.isoformat() if isinstance(e.fetched_at, datetime) else e.fetched_at,
            )
            for e in epss_list  # ← non usare range(len()), non è pythonic
        ]
        query = """
            INSERT INTO epss_scores (
                cve_id, epss_score, epss_percentile, fetched_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                epss_score = excluded.epss_score,
                epss_percentile = excluded.epss_percentile,
                fetched_at = excluded.fetched_at
        """
        with self._get_connection() as conn:
            conn.executemany(query, data)
