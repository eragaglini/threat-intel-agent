import pytest
import os
import json
import shutil
from layer2.graph import save_report_node
from layer2.models.state import AgentState

@pytest.fixture
def mock_state_with_report():
    return AgentState(
        cve_id="CVE-2023-TEST",
        raw_data={},
        enriched_data={},
        impacted_assets=["SRV-1"],
        is_relevant=True,
        adjusted_risk_score=9.0,
        risk_score=7.5,
        risk_level="HIGH",
        ttp_mappings=[],
        reflexion_count=0,
        confidence_scores={},
        errors=[],
        final_report={
            "narrative": "Test narrative summary.",
            "structured_json": "{}"
        }
    )

def test_save_report_node_creates_file(mock_state_with_report):
    # Setup - clear reports directory if exists
    if os.path.exists("reports"):
        shutil.rmtree("reports")
    
    # Execute
    save_report_node(mock_state_with_report)
    
    # Assert
    assert os.path.exists("reports")
    files = os.listdir("reports")
    assert len(files) == 1
    assert files[0].startswith("report_CVE-2023-TEST")
    
    # Verify content
    with open(f"reports/{files[0]}", "r") as f:
        data = json.load(f)
        assert data["cve_id"] == "CVE-2023-TEST"
        assert data["impacted_assets"] == ["SRV-1"]
        assert data["analysis"] == "Test narrative summary."
    
    # Clean up
    shutil.rmtree("reports")
