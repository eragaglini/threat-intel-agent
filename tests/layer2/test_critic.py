from layer2.nodes.critic import critic_node
from layer2.models.state import AgentState

def test_critic_pass():
    state = AgentState(
        cve_id="CVE-OK",
        ttp_mappings=[{"id": "T1"}, {"id": "2"}], # At least 2
        confidence_scores={"attck_mapping": 0.8}, # > 0.5
        errors=[],
        raw_data={"cvss_score": 7.5}
    )
    
    new_state = critic_node(state)
    assert len(new_state["errors"]) == 0

def test_critic_fail_low_ttp_count():
    state = AgentState(
        cve_id="CVE-FAIL",
        ttp_mappings=[{"id": "T1"}], # Only 1
        confidence_scores={"attck_mapping": 0.8},
        errors=[],
        raw_data={"cvss_score": 7.5}
    )
    
    new_state = critic_node(state)
    assert any("Less than 2 TTPs" in err for err in new_state["errors"])

def test_critic_fail_low_confidence():
    state = AgentState(
        cve_id="CVE-FAIL",
        ttp_mappings=[{"id": "T1"}, {"id": "T2"}],
        confidence_scores={"attck_mapping": 0.4}, # Too low
        errors=[],
        raw_data={"cvss_score": 7.5}
    )
    
    new_state = critic_node(state)
    assert any("confidence too low" in err for err in new_state["errors"])
