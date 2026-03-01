from layer2.graph import route_from_critic
from layer2.models.state import AgentState

def test_route_from_critic_retry():
    # Errors exist and reflexion_count < 2 (already incremented by node) -> should retry
    state = AgentState(
        errors=["Invalid TTPs"],
        reflexion_count=1
    )
    result = route_from_critic(state)
    assert result == "attck_mapper"
    # Router should not modify state, count remains 1
    assert state["reflexion_count"] == 1

def test_route_from_critic_limit_reached():
    # Errors exist but reflexion_count is at limit -> proceed to report
    state = AgentState(
        errors=["Invalid TTPs"],
        reflexion_count=2
    )
    result = route_from_critic(state)
    assert result == "report_generator"

def test_route_from_critic_pass():
    # No errors -> proceed to report
    state = AgentState(
        errors=[],
        reflexion_count=0
    )
    result = route_from_critic(state)
    assert result == "report_generator"
