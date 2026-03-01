import logging
from typing import Dict, Any, List
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from layer2.models.state import AgentState, TTP
from layer2.config import LLM_CONFIG, LLM_OPTIONS
from layer2.utils.llm_invoker import invoke_chain_with_retry

logger = logging.getLogger(__name__)

class TTPList(BaseModel):
    ttps: List[TTP] = Field(description="List of mapped MITRE ATT&CK techniques")

# Prompt migliorato con vincoli espliciti sul mapping ATT&CK
ATTCK_PROMPT = PromptTemplate.from_template(
    "You are a MITRE ATT&CK expert. Map the following CVE to ATT&CK techniques.\n\n"
    "STRICT RULES:\n"
    "1. Use ONLY valid, existing ATT&CK technique IDs from the official MITRE ATT&CK framework.\n"
    "2. Do NOT invent technique IDs or names. When in doubt, omit the technique.\n"
    "3. Common valid techniques for vulnerabilities: T1190 (Exploit Public-Facing Application), "
    "T1059 (Command and Scripting Interpreter), T1068 (Exploitation for Privilege Escalation), "
    "T1210 (Exploitation of Remote Services), T1203 (Exploitation for Client Execution).\n"
    "4. T1106 is 'Native API', NOT 'Execute Remote File'. Use it only if the CVE involves "
    "direct OS API calls by malware.\n"
    "5. Assign confidence scores honestly: 0.9+ only if the technique is clearly documented.\n\n"
    "CVE Description: {description}\n"
    "Enriched Data: {enriched_data}\n\n"
    "Return a list of relevant ATT&CK techniques with technique_id, name, and confidence."
)

def attck_mapper_node(state: AgentState) -> Dict[str, Any]:
    """
    Mappa la CVE a tecniche MITRE ATT&CK.
    Ritorna solo i campi aggiornati, senza mutare lo state.
    """
    cve_id = state.get("cve_id", "UNKNOWN")
    logger.info(f"--- ATT&CK MAPPER NODE for {cve_id} ---")

    llm = ChatAnthropic(model=LLM_CONFIG["attck_mapping"], **LLM_OPTIONS)
    structured_llm = llm.with_structured_output(TTPList)
    chain = ATTCK_PROMPT | structured_llm

    description = state.get("raw_data", {}).get("description", "No description available")
    enriched_data = str(state.get("enriched_data", {}))

    try:
        result: TTPList = invoke_chain_with_retry(
            chain,
            {"description": description, "enriched_data": enriched_data}
        )

        ttp_list = [ttp.model_dump() for ttp in result.ttps]
        max_conf = max((ttp.confidence for ttp in result.ttps), default=0.0)

        logger.info(f"[{cve_id}] Mapped {len(ttp_list)} ATT&CK techniques. Max confidence: {max_conf:.2f}")

        # ✅ Ritorna SOLO i campi aggiornati
        return {
            "ttp_mappings": ttp_list,
            "confidence_scores": {
                **state.get("confidence_scores", {}),  # Preserva score esistenti
                "attck_mapping": max_conf
            }
        }

    except Exception as e:
        logger.error(f"[{cve_id}] Error in ATT&CK mapping: {e}")
        return {
            "ttp_mappings": [],
            "errors": state.get("errors", []) + [f"ATT&CK mapping failed: {str(e)}"],
            "confidence_scores": {
                **state.get("confidence_scores", {}),
                "attck_mapping": 0.0
            }
        }