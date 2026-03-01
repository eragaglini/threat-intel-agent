import os
import sqlite3
import logging
from dotenv import load_dotenv
from langgraph.checkpoint.sqlite import SqliteSaver

import sys
# Ensure the root of the project is in the PYTHONPATH to access src
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from layer1.database.database import DatabaseManager
from layer2.graph import build_graph
from layer2.models.state import AgentState

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def main():
    load_dotenv()
    if not os.getenv("ANTHROPIC_API_KEY"):
        logger.error("ANTHROPIC_API_KEY is not set in .env")
        return

    db_manager = DatabaseManager(db_path="threat_intel.db")
    # Fetch top 2 critical exploited CVEs for PoC
    critical_cves = db_manager.get_critical_exploited_cves(min_cvss=7.0, limit=2)
    
    if not critical_cves:
        logger.info("No critical exploited CVEs found. Run Layer 1 ingestion first.")
        return

    logger.info(f"Found {len(critical_cves)} critical CVEs to process.")

    workflow = build_graph()
    
    # Initialize SQLite Checkpointer
    with sqlite3.connect("layer2_checkpoints.db", check_same_thread=False) as conn:
        checkpointer = SqliteSaver(conn)
        app = workflow.compile(checkpointer=checkpointer)

        for cve in critical_cves:
            cve_id = cve["id"]
            logger.info(f"=== Processing Layer 2 Pipeline for {cve_id} ===")

            # Log EPSS per visibilità immediata
            epss_val = cve.get("epss_score")
            if epss_val is not None:
                logger.info(f"[{cve_id}] EPSS score from DB: {epss_val:.4f}")
            else:
                logger.warning(f"[{cve_id}] EPSS score non disponibile nel DB.")

            initial_state = AgentState(
                cve_id=cve_id,
                raw_data=dict(cve),         # ← ora include epss_score grazie al JOIN
                enriched_data=None,
                risk_score=None,            # ← None, non 0.0: viene calcolato da risk_scorer
                risk_level=None,
                adjusted_risk_score=None,   # ← aggiunto
                risk_adjustment=None,       # ← aggiunto
                impacted_assets=[],         # ← aggiunto
                is_relevant=False,          # ← aggiunto
                ttp_mappings=[],
                reflexion_count=0,
                confidence_scores={"enrichment": 0.0, "attck_mapping": 0.0},
                errors=[],
                final_report=None
            )
            
            thread_config = {"configurable": {"thread_id": f"thread_{cve_id}"}}
            
            for event in app.stream(initial_state, config=thread_config):
                for key, value in event.items():
                    logger.info(f"Node '{key}' completed.")
            
            final_state = app.get_state(thread_config).values
            logger.info(f"\\n=== Final Report for {cve_id} ===")
            if final_state.get("final_report"):
                print(final_state["final_report"]["narrative"])
                print("\\nStructured JSON:")
                print(final_state["final_report"]["structured_json"])
            else:
                print("No report generated.")
            print("-" * 80)

if __name__ == "__main__":
    main()
