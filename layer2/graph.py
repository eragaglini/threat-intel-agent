import logging
import os
import json
from datetime import datetime
from langgraph.graph import StateGraph, END, START
from layer2.models.state import AgentState
from layer2.nodes.cve_enrichment import cve_enrichment_node
from layer2.nodes.asset_matcher import asset_matcher_node
from layer2.nodes.risk_scorer import risk_scorer_node
from layer2.nodes.attck_mapper import attck_mapper_node
from layer2.nodes.critic import critic_node
from layer2.nodes.report_generator import report_generator_node

logger = logging.getLogger(__name__)

# Costante per il numero massimo di cicli di riflessione
MAX_REFLEXION_CYCLES = 2

def save_report_node(state: AgentState):
    """
    Persists the final report to the filesystem.
    """
    report = state.get("final_report")
    if not report:
        logger.warning("No report found to save.")
        return {}

    cve_id = state.get("cve_id", "unknown_cve")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    os.makedirs("reports", exist_ok=True)
    filename = f"reports/report_{cve_id}_{timestamp}.json"

    # Recupera i dati di aggiustamento del rischio
    risk_adjustment = state.get("risk_adjustment", {})

    report_data = {
        "cve_id": cve_id,
        "impacted_assets": state.get("impacted_assets", []),
        "is_relevant": state.get("is_relevant", False),
        "original_risk_score": state.get("risk_score"),       # None se non calcolato
        "adjusted_risk_score": state.get("adjusted_risk_score"),  # None se non calcolato
        "risk_adjustment": risk_adjustment,                   # Trasparenza sul calcolo
        "ttp_mappings": state.get("ttp_mappings", []),
        "reflexion_cycles": state.get("reflexion_count", 0),  # Quante volte il critic è intervenuto
        "analysis": report.get("narrative", ""),
        "generated_at": timestamp
    }

    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)

    logger.info(f"Report saved to {filename}")
    return {}


def route_from_attck(state: AgentState) -> str:
    """
    Routing sempre verso critic dopo attck_mapper.
    Mantenuto come conditional edge per future logiche di branching.
    """
    return "critic"


def route_from_critic(state: AgentState) -> str:
    """
    Se il critic ha rilevato errori e non abbiamo superato
    il numero massimo di cicli, torna ad attck_mapper per riflessione.
    Altrimenti procede alla generazione del report.
    """
    has_errors = bool(state.get("errors"))
    reflexion_count = state.get("reflexion_count", 0)

    if has_errors and reflexion_count < MAX_REFLEXION_CYCLES:
        logger.info(
            f"Critic ha rilevato errori (ciclo {reflexion_count + 1}/{MAX_REFLEXION_CYCLES}). "
            f"Ritorno ad attck_mapper per riflessione."
        )
        return "attck_mapper"

    if has_errors:
        logger.warning(
            f"Errori persistenti dopo {reflexion_count} cicli di riflessione. "
            f"Procedo alla generazione del report con i dati disponibili."
        )

    return "report_generator"


def build_graph():
    workflow = StateGraph(AgentState)

    # --- Registrazione Nodi ---
    workflow.add_node("cve_enrichment", cve_enrichment_node)
    workflow.add_node("risk_scorer", risk_scorer_node)       # Spostato prima di asset_matcher
    workflow.add_node("asset_matcher", asset_matcher_node)   # Ora legge risk_score già calcolato
    workflow.add_node("attck_mapper", attck_mapper_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("report_generator", report_generator_node)
    workflow.add_node("save_report", save_report_node)

    # --- Definizione Flusso ---
    #
    # START
    #   └─→ cve_enrichment      (fetch dati grezzi, arricchimento)
    #         └─→ risk_scorer   (calcola risk_score da EPSS, CVSS, KEV)
    #               └─→ asset_matcher  (legge risk_score, calcola adjusted_risk_score)
    #                     └─→ attck_mapper  (mappa TTP su ATT&CK)
    #                           └─→ [critic]
    #                                 ├─→ attck_mapper  (se errori e < MAX_REFLEXION_CYCLES)
    #                                 └─→ report_generator
    #                                       └─→ save_report
    #                                             └─→ END

    workflow.add_edge(START, "cve_enrichment")
    workflow.add_edge("cve_enrichment", "risk_scorer")    # FIX: risk_scorer prima
    workflow.add_edge("risk_scorer", "asset_matcher")     # FIX: asset_matcher dopo
    workflow.add_edge("asset_matcher", "attck_mapper")

    workflow.add_conditional_edges(
        "attck_mapper",
        route_from_attck,
        {"critic": "critic"}
    )

    workflow.add_conditional_edges(
        "critic",
        route_from_critic,
        {
            "attck_mapper": "attck_mapper",
            "report_generator": "report_generator"
        }
    )

    workflow.add_edge("report_generator", "save_report")
    workflow.add_edge("save_report", END)

    return workflow