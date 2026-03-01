import logging
from layer2.models.state import AgentState

logger = logging.getLogger(__name__)

def critic_node(state: AgentState) -> AgentState:
    logger.info(f"--- CRITIC NODE for {state.get('cve_id')} ---")
    
    errors = []
    is_valid = True
    
    # 1. At least 2 TTPs mapped?
    ttps = state.get("ttp_mappings", [])
    if len(ttps) < 2:
        errors.append("Less than 2 TTPs mapped.")
        is_valid = False
        
    # 2. CVSS consistent?
    cvss = float(state.get("raw_data", {}).get("cvss_score") or 0.0)
    if cvss == 0.0:
        logger.warning("CVSS is 0.0, might be missing.")
        
    # 3. Validation of Confidence
    attck_conf = state.get("confidence_scores", {}).get("attck_mapping", 0.0)
    if attck_conf <= 0.5:
        errors.append(f"ATT&CK mapping confidence too low: {attck_conf}")
        is_valid = False
        
    if not is_valid:
        logger.warning(f"Critic failed validation. Errors: {errors}")
        state["errors"].extend(errors)
        # Increment reflexion count only if we are sending it back
        current_reflexion = state.get("reflexion_count", 0)
        if current_reflexion < 2:
            state["reflexion_count"] = current_reflexion + 1
    else:
        logger.info("Critic validation passed.")
        
    return state
