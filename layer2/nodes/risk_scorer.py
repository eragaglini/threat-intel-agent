import logging
from layer2.models.state import AgentState

logger = logging.getLogger(__name__)

def risk_scorer_node(state: AgentState) -> AgentState:
    logger.info(f"--- RISK SCORER NODE for {state.get('cve_id')} ---")
    
    raw_data = state.get("raw_data", {})
    
    # Extract CVSS
    cvss = float(raw_data.get("cvss_score") or 0.0)
    
    # EPSS - Using a default if missing for PoC, as it might require a join with epss_scores table
    epss = float(raw_data.get("epss_score") or 0.05) 
    
    # KEV Flag
    known_ransomware = raw_data.get("known_ransomware_campaign_use")
    kev_flag = 1.0 if known_ransomware and known_ransomware.lower() not in ["none", "unknown", ""] else 0.0
    
    # Normalizing CVSS to 0-1 for the calculation
    normalized_cvss = cvss / 10.0
    risk_score = (normalized_cvss * 0.4) + (epss * 0.4) + (kev_flag * 0.2)
    
    state["risk_score"] = risk_score
    state["risk_level"] = "high_risk" if risk_score >= 0.6 else "low_risk"
    
    logger.info(f"Computed Risk Score: {risk_score:.3f} ({state['risk_level']})")
    
    return state
