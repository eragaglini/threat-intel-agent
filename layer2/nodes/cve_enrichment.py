import logging
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import PromptTemplate
from layer2.models.state import AgentState, EnrichedData

logger = logging.getLogger(__name__)

def cve_enrichment_node(state: AgentState) -> AgentState:
    logger.info(f"--- CVE ENRICHMENT NODE for {state.get('cve_id')} ---")
    
    llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0)
    structured_llm = llm.with_structured_output(EnrichedData)
    
    prompt = PromptTemplate.from_template(
        "Analyze the following CVE data and extract the affected component, attack vector, impact type, and CWE.\n"
        "If some information is not explicitly stated, infer it logically based on the description.\n\n"
        "CVE Data:\n{raw_data}"
    )
    
    chain = prompt | structured_llm
    
    try:
        raw_data_str = str(state["raw_data"])
        result: EnrichedData = chain.invoke({"raw_data": raw_data_str})
        
        state["enriched_data"] = result.model_dump()
        state["confidence_scores"]["enrichment"] = 0.9  # Assumed baseline confidence
    except Exception as e:
        logger.error(f"Error in enrichment: {e}")
        state["errors"].append(f"Enrichment failed: {str(e)}")
        state["enriched_data"] = {}
        state["confidence_scores"]["enrichment"] = 0.0

    return state
