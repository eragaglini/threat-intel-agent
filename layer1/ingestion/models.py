from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime

class CVEModel(BaseModel):
    id: str = Field(..., description="CVE ID (e.g., CVE-2023-12345)")
    description: str
    published: datetime
    last_modified: datetime
    cvss_score: Optional[float] = None
    references: List[HttpUrl] = []

class KEVModel(BaseModel):
    cve_id: str = Field(..., alias="cveID")
    vendor_project: str = Field(..., alias="vendorProject")
    product: str
    vulnerability_name: str = Field(..., alias="vulnerabilityName")
    date_added: datetime = Field(..., alias="dateAdded")
    short_description: str = Field(..., alias="shortDescription")
    required_action: str = Field(..., alias="requiredAction")
    due_date: datetime = Field(..., alias="dueDate")
    known_ransomware_campaign_use: str = Field(..., alias="knownRansomwareCampaignUse")

class ReportModel(BaseModel):
    reported_at: datetime = Field(..., alias="reportedAt")
    comment: Optional[str] = None
    categories: List[int] = []
    reporter_id: int = Field(..., alias="reporterId")
    reporter_country_code: Optional[str] = Field(None, alias="reporterCountryCode")
    reporter_country_name: Optional[str] = Field(None, alias="reporterCountryName")

class IPReputationModel(BaseModel):
    ip_address: str = Field(..., alias="ipAddress")
    is_public: bool = Field(..., alias="isPublic")
    ip_version: int = Field(..., alias="ipVersion")
    is_whitelisted: Optional[bool] = Field(None, alias="isWhitelisted")
    abuse_confidence_score: int = Field(..., alias="abuseConfidenceScore")
    country_code: Optional[str] = Field(None, alias="countryCode")
    usage_type: Optional[str] = Field(None, alias="usageType")
    isp: Optional[str] = Field(None)
    domain: Optional[str] = Field(None)
    total_reports: int = Field(..., alias="totalReports")
    last_reported_at: Optional[datetime] = Field(None, alias="lastReportedAt")
    reports: List[ReportModel] = []

class EPSSModel(BaseModel):
    cve_id: str = Field(..., alias="cve")
    epss_score: float = Field(..., alias="epss")
    epss_percentile: float = Field(..., alias="percentile")
    fetched_at: datetime = Field(default_factory=datetime.now)
