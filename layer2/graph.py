import logging
from langgraph.graph import StateGraph, END, START
from layer2.models.state import AgentState
from layer2.nodes.cve_enrichment import cve_enrichment_node
from layer2.nodes.risk_scorer import risk_scorer_node
from layer2.nodes.attck_mapper import attck_mapper_node
from layer2.nodes.critic import critic_node
from layer2.nodes.report_generator import report_generator_node

logger = logging.getLogger(__name__)

def route_from_attck(state: AgentState):
    max_conf = state.get("confidence_scores", {}).get("attck_mapping", 0.0)
    if max_conf <= 0.5:
        return "critic"
    return "critic"

def route_from_critic(state: AgentState):
    if state.get("errors") and state.get("reflexion_count", 0) < 2:
        state["reflexion_count"] = state.get("reflexion_count", 0) + 1
        # Retry logic: we send back to attck_mapper to attempt a better mapping
        # State manipulation should ideally happen in nodes, but we mutated reflexion_count here for simplicity
        return "attck_mapper"
    return "report_generator"

def build_graph():
    workflow = StateGraph(AgentState)

    # Add Nodes
    workflow.add_node("cve_enrichment", cve_enrichment_node)
    workflow.add_node("risk_scorer", risk_scorer_node)
    workflow.add_node("attck_mapper", attck_mapper_node)
    workflow.add_node("critic", critic_node)
    workflow.add_node("report_generator", report_generator_node)

    # Add Edges
    workflow.add_edge(START, "cve_enrichment")
    workflow.add_edge("cve_enrichment", "risk_scorer")
    workflow.add_edge("risk_scorer", "attck_mapper")
    
    workflow.add_conditional_edges(
        "attck_mapper",
        route_from_attck,
        {
            "critic": "critic"
        }
    )
    
    workflow.add_conditional_edges(
        "critic",
        route_from_critic,
        {
            "attck_mapper": "attck_mapper",
            "report_generator": "report_generator"
        }
    )
    
    workflow.add_edge("report_generator", END)

    return workflow
