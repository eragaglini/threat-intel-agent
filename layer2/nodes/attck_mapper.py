import logging
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field
from typing import List
from layer2.models.state import AgentState, TTP
from layer2.config import LLM_CONFIG, LLM_OPTIONS
from layer2.utils.llm_invoker import invoke_chain_with_retry

logger = logging.getLogger(__name__)

class TTPList(BaseModel):
    ttps: List[TTP] = Field(description="List of mapped MITRE ATT&CK techniques")

def attck_mapper_node(state: AgentState) -> AgentState:
    logger.info(f"--- ATT&CK MAPPER NODE for {state.get('cve_id')} ---")
    
    llm = ChatAnthropic(
        model=LLM_CONFIG["attck_mapping"], 
        **LLM_OPTIONS
    )
    structured_llm = llm.with_structured_output(TTPList)
    
    prompt = PromptTemplate.from_template(
        "Map the following CVE description and enriched data to MITRE ATT&CK techniques.\n"
        "Provide a list of relevant techniques with their technique ID (e.g., T1190), name, and your confidence score (0.0 to 1.0).\n\n"
        "CVE Description: {description}\n"
        "Enriched Data: {enriched_data}"
    )
    
    chain = prompt | structured_llm
    
    description = state.get("raw_data", {}).get("description", "")
    enriched_data = str(state.get("enriched_data", {}))
    
    try:
        result: TTPList = invoke_chain_with_retry(chain, {"description": description, "enriched_data": enriched_data})
        state["ttp_mappings"] = [ttp.model_dump() for ttp in result.ttps]
        
        # Calculate overall mapping confidence safely
        if result.ttps:
            max_conf = max([ttp.confidence for ttp in result.ttps])
        else:
            max_conf = 0.0
            
        state["confidence_scores"]["attck_mapping"] = max_conf
        
    except Exception as e:
        logger.error(f"Error in ATT&CK mapping: {e}")
        state["errors"].append(f"ATT&CK mapping failed: {str(e)}")
        state["ttp_mappings"] = []
        state["confidence_scores"]["attck_mapping"] = 0.0

    return state
