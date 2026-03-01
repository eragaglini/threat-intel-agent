import logging
from typing import Dict, Any
from layer2.models.state import AgentState

logger = logging.getLogger(__name__)

def risk_scorer_node(state: AgentState) -> Dict[str, Any]:
    """
    Calcola il risk score basandosi su CVSS, EPSS e KEV flag.
    Ritorna solo i campi aggiornati, senza mutare lo state.
    """
    cve_id = state.get("cve_id", "UNKNOWN")
    logger.info(f"--- RISK SCORER NODE for {cve_id} ---")

    raw_data = state.get("raw_data", {})

    # --- CVSS ---
    cvss = float(raw_data.get("cvss_score") or 0.0)
    normalized_cvss = cvss / 10.0

    # --- EPSS ---
    epss_raw = raw_data.get("epss_score")
    if epss_raw is None:
        # Default conservativo per PoC — logga il fatto per trasparenza
        epss = 0.05
        logger.warning(
            f"[{cve_id}] epss_score assente in raw_data. "
            f"Usato default={epss}. Considera di arricchire i dati EPSS."
        )
    else:
        epss = float(epss_raw)

    # --- KEV Flag ---
    known_ransomware = raw_data.get("known_ransomware_campaign_use", "")
    kev_flag = 1.0 if known_ransomware and known_ransomware.lower() not in [
        "none", "unknown", "", "n/a"
    ] else 0.0

    # --- Formula Risk Score ---
    # Pesi: CVSS 40% | EPSS 40% | KEV 20%
    risk_score = (normalized_cvss * 0.4) + (epss * 0.4) + (kev_flag * 0.2)
    risk_level = "high_risk" if risk_score >= 0.6 else "low_risk"

    logger.info(
        f"[{cve_id}] Risk Score: {risk_score:.4f} ({risk_level}) | "
        f"CVSS={cvss} EPSS={epss} KEV={kev_flag}"
    )

    # ✅ Ritorna SOLO i campi aggiornati — LangGraph fa il merge
    return {
        "risk_score": round(risk_score, 4),
        "risk_level": risk_level
    }