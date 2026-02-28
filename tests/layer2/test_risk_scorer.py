from layer2.nodes.risk_scorer import risk_scorer_node
from layer2.models.state import AgentState

def test_risk_scorer_high_risk():
    state = AgentState(
        cve_id="CVE-HIGH",
        raw_data={
            "cvss_score": 9.8,
            "epss_score": 0.9,
            "known_ransomware_campaign_use": "Known"
        },
        risk_score=0.0,
        risk_level="",
        errors=[]
    )
    
    new_state = risk_scorer_node(state)
    
    # calculation: (0.98 * 0.4) + (0.9 * 0.4) + (1.0 * 0.2) = 0.392 + 0.36 + 0.2 = 0.952
    assert new_state["risk_score"] > 0.9
    assert new_state["risk_level"] == "high_risk"

def test_risk_scorer_low_risk():
    state = AgentState(
        cve_id="CVE-LOW",
        raw_data={
            "cvss_score": 3.0,
            "epss_score": 0.01,
            "known_ransomware_campaign_use": None
        },
        risk_score=0.0,
        risk_level="",
        errors=[]
    )
    
    new_state = risk_scorer_node(state)
    
    assert new_state["risk_level"] == "low_risk"
    assert new_state["risk_score"] < 0.3
