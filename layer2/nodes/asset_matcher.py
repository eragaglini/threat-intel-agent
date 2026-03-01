import json
import os
import logging
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from layer2.models.state import AgentState

logger = logging.getLogger(__name__)

class AssetMatchResult(BaseModel):
    impacted_asset_ids: List[str] = Field(description="IDs of the assets that are likely vulnerable to the CVE")
    is_relevant: bool = Field(description="True if at least one asset is potentially impacted")
    reasoning: str = Field(description="Brief explanation of why these assets were matched")
    impact_level: str = Field(description="Impact level on the infrastructure: LOW, MEDIUM, HIGH, CRITICAL")

def asset_matcher_node(state: AgentState) -> Dict[str, Any]:
    """
    Compares the CVE enriched data with the internal asset inventory (CMDB).
    """
    logger.info(f"Starting Asset Matching for {state['cve_id']}...")
    
    # 1. Load Assets
    assets_path = "assets.json"
    if not os.path.exists(assets_path):
        logger.error(f"Assets file {assets_path} not found.")
        return {"errors": ["Asset file not found"], "is_relevant": False, "impacted_assets": []}
    
    with open(assets_path, "r") as f:
        assets = json.load(f)

    # 2. Setup LLM (Claude)
    llm = ChatAnthropic(model="claude-3-haiku-20240307", temperature=0)
    structured_llm = llm.with_structured_output(AssetMatchResult)

    # 3. Create Prompt
    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a Cybersecurity Asset Management Expert. Your goal is to determine if a specific vulnerability (CVE) impacts a company's internal assets based on their software inventory and OS."),
        ("human", """
        COMPARE THE VULNERABILITY DATA WITH THE ASSET INVENTORY.
        
        VULNERABILITY DATA (CVE: {cve_id}):
        - Description: {description}
        - Affected Component (Analysis): {affected_component}
        
        INTERNAL ASSET INVENTORY (CMDB):
        {assets_json}
        
        INSTRUCTIONS:
        1. Look for matches between 'Affected Component' and the asset's 'software' or 'os'.
        2. Be conservative: if a component name matches but versions are drastically different, note it.
        3. If no assets match, set is_relevant to false and return an empty list.
        """)
    ])

    chain = prompt | structured_llm

    # 4. Invoke LLM
    try:
        enriched = state.get("enriched_data", {})
        result: AssetMatchResult = chain.invoke({
            "cve_id": state["cve_id"],
            "description": state["raw_data"].get("description", "No description available"),
            "affected_component": enriched.get("affected_component", "Unknown"),
            "assets_json": json.dumps(assets, indent=2)
        })

        # 5. Calculate Adjusted Risk Score
        # Simple logic: if relevant, increase risk score by 20%, max 10.0
        base_score = state.get("risk_score")

        if base_score is None:
            logger.warning(f"[{state['cve_id']}] risk_score assente. adjusted_risk_score non calcolabile.")
            adjusted_score = None
            risk_adjustment = {
                "original_score": None,
                "adjusted_score": None,
                "multiplier_applied": None,
                "impact_level": result.impact_level,
                "rationale": "Score non calcolabile: risk_score non disponibile nello state."
            }
        else:
            if result.is_relevant:
                multiplier = 1.2 if result.impact_level in ["HIGH", "CRITICAL"] else 1.1
                adjusted_score = round(min(10.0, base_score * multiplier), 4)
                risk_adjustment = {
                    "original_score": base_score,
                    "adjusted_score": adjusted_score,
                    "multiplier_applied": multiplier,
                    "impact_level": result.impact_level,
                    "rationale": (
                        f"Asset '{result.impacted_asset_ids}' impattato "
                        f"(impact_level={result.impact_level}). "
                        f"Moltiplicatore {multiplier}x applicato."
                    )
                }
            else:
                adjusted_score = base_score
                risk_adjustment = {
                    "original_score": base_score,
                    "adjusted_score": adjusted_score,
                    "multiplier_applied": 1.0,
                    "impact_level": result.impact_level,
                    "rationale": "Nessun asset impattato: score invariato."
                }

        logger.info(
            f"[{state['cve_id']}] Risk score: {base_score} → {adjusted_score} "
            f"(impact_level={result.impact_level}, relevant={result.is_relevant})"
        )

        return {
            "impacted_assets": result.impacted_asset_ids,
            "is_relevant": result.is_relevant,
            "adjusted_risk_score": adjusted_score,
            "risk_adjustment": risk_adjustment      # ← ora popolato
        }

    except Exception as e:
        logger.error(f"Error in asset_matcher_node: {e}")
        return {
            "errors": [f"Asset matcher error: {str(e)}"],
            "is_relevant": False,
            "impacted_assets": []
        }
