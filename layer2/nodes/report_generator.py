import logging
import json
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import PromptTemplate
from layer2.models.state import AgentState, Report
from layer2.config import LLM_CONFIG, LLM_OPTIONS
from layer2.utils.llm_invoker import invoke_chain_with_retry

logger = logging.getLogger(__name__)

def report_generator_node(state: AgentState) -> AgentState:
    logger.info(f"--- REPORT GENERATOR NODE for {state.get('cve_id')} ---")
    
    llm = ChatAnthropic(
        model=LLM_CONFIG["report_generation"], 
        **LLM_OPTIONS
    )
    structured_llm = llm.with_structured_output(Report)
    
    prompt = PromptTemplate.from_template(
        "Generate a Threat Intelligence report for SOC analysts based on the following state data.\n"
        "Include a narrative summary outlining the risk and a structured JSON representation.\n\n"
        "State Data: {state_data}"
    )
    
    chain = prompt | structured_llm
    
    try:
        state_data = {
            "cve_id": state.get("cve_id"),
            "risk_level": state.get("risk_level"),
            "risk_score": state.get("risk_score"),
            "enriched_data": state.get("enriched_data"),
            "ttp_mappings": state.get("ttp_mappings"),
            "vulnerability_name": state.get("raw_data", {}).get("vulnerability_name")
        }
        
        result: Report = invoke_chain_with_retry(chain, {"state_data": json.dumps(state_data)})
        
        state["final_report"] = {
            "narrative": result.narrative,
            "structured_json": result.structured_json
        }
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        state["errors"].append(f"Report generation failed: {str(e)}")
        state["final_report"] = None

    return state
