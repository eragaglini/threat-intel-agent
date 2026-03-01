import logging
import json
from typing import Dict, Any
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import PromptTemplate
from layer2.models.state import AgentState, Report
from layer2.config import LLM_CONFIG, LLM_OPTIONS
from layer2.utils.llm_invoker import invoke_chain_with_retry

logger = logging.getLogger(__name__)

def report_generator_node(state: AgentState) -> Dict[str, Any]:
    cve_id = state.get("cve_id", "UNKNOWN")
    logger.info(f"--- REPORT GENERATOR NODE for {cve_id} ---")

    llm = ChatAnthropic(model=LLM_CONFIG["report_generation"], **LLM_OPTIONS)
    structured_llm = llm.with_structured_output(Report)

    prompt = PromptTemplate.from_template(
        "Generate a Threat Intelligence report for SOC analysts based on the following data.\n"
        "The report must include:\n"
        "1. A narrative summary explaining the risk in plain language\n"
        "2. Specific recommended mitigations\n"
        "3. A structured JSON representation including ALL fields provided\n\n"
        "IMPORTANT: The JSON must include both 'original_risk_score' and 'adjusted_risk_score'.\n"
        "If adjusted_risk_score differs from original, explain why in the narrative.\n\n"
        "Data: {state_data}"
    )

    chain = prompt | structured_llm

    try:
        # Tutti i campi rilevanti passati a Claude
        state_data = {
            "cve_id": cve_id,
            "vulnerability_name": state.get("raw_data", {}).get("vulnerability_name"),
            "risk_level": state.get("risk_level"),
            "original_risk_score": state.get("risk_score"),
            "adjusted_risk_score": state.get("adjusted_risk_score"),
            "risk_adjustment": state.get("risk_adjustment", {}),
            "impacted_assets": state.get("impacted_assets", []),
            "is_relevant": state.get("is_relevant", False),
            "enriched_data": state.get("enriched_data", {}),
            "ttp_mappings": state.get("ttp_mappings", []),
            "reflexion_cycles": state.get("reflexion_count", 0),
        }

        result: Report = invoke_chain_with_retry(
            chain,
            {"state_data": json.dumps(state_data, indent=2)}
        )

        logger.info(f"[{cve_id}] Report generated successfully.")

        # ✅ Ritorna solo i campi aggiornati
        return {
            "final_report": {
                "narrative": result.narrative,
                "structured_json": result.structured_json
            }
        }

    except Exception as e:
        logger.error(f"[{cve_id}] Error generating report: {e}")
        return {
            "final_report": None,
            "errors": state.get("errors", []) + [f"Report generation failed: {str(e)}"]
        }