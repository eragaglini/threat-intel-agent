from typing import TypedDict, List, Dict, Any, Optional
from pydantic import BaseModel, Field

class EnrichedData(BaseModel):
    affected_component: str = Field(description="The software, hardware, or component affected by the vulnerability")
    attack_vector: str = Field(description="How the attack is executed (e.g., Network, Local, Physical)")
    impact_type: str = Field(description="The type of impact (e.g., RCE, DoS, Privilege Escalation)")
    cwe: str = Field(description="The CWE ID representing the weakness type, e.g., CWE-79")

class TTP(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK Technique ID, e.g., T1190")
    name: str = Field(description="Name of the technique")
    confidence: float = Field(description="Confidence score between 0.0 and 1.0")

class Report(BaseModel):
    narrative: str = Field(description="Narrative summary for SOC analysts")
    structured_json: str = Field(description="Structured JSON representation")

class AgentState(TypedDict):
    cve_id: str
    raw_data: Dict[str, Any]
    enriched_data: Optional[Dict[str, Any]]
    risk_score: float
    risk_level: str
    ttp_mappings: List[Dict[str, Any]]
    reflexion_count: int
    confidence_scores: Dict[str, float]
    errors: List[str]
    final_report: Optional[Dict[str, Any]]
