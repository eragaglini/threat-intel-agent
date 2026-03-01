import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.asset_matcher import asset_matcher_node, AssetMatchResult
from layer2.models.state import AgentState

@pytest.fixture
def mock_state():
    return AgentState(
        cve_id="CVE-2023-1234",
        raw_data={"description": "Vulnerability in Windows Server"},
        enriched_data={"affected_component": "Windows Server"},
        impacted_assets=[],
        is_relevant=False,
        adjusted_risk_score=0.0,
        risk_score=7.5,
        risk_level="HIGH",
        ttp_mappings=[],
        reflexion_count=0,
        confidence_scores={},
        errors=[],
        final_report=None
    )

@patch("layer2.nodes.asset_matcher.ChatAnthropic")
@patch("os.path.exists")
@patch("builtins.open")
def test_asset_matcher_match_found(mock_open, mock_exists, mock_llm_class, mock_state):
    # Setup
    mock_exists.return_value = True
    mock_open.return_value.__enter__.return_value.read.return_value = '[{"id": "SRV-1", "name": "Windows Server"}]'
    
    mock_llm = MagicMock()
    mock_llm_class.return_value = mock_llm
    
    mock_result = AssetMatchResult(
        impacted_asset_ids=["SRV-1"],
        is_relevant=True,
        reasoning="Matched Windows Server",
        impact_level="HIGH"
    )
    
    # We mock the chain.invoke directly by patching the RunnableSequence or by patching the result of the '|' operator
    # The most reliable way is to mock 'prompt | structured_llm' result.
    with patch("langchain_core.prompts.ChatPromptTemplate.from_messages") as mock_prompt_class:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = mock_result
        mock_prompt_class.return_value.__or__.return_value = mock_chain
        
        # Execute
        result = asset_matcher_node(mock_state)
    
    # Assert
    assert result["is_relevant"] is True
    assert "SRV-1" in result["impacted_assets"]
    assert result["adjusted_risk_score"] > 7.5

@patch("layer2.nodes.asset_matcher.ChatAnthropic")
@patch("os.path.exists")
@patch("builtins.open")
def test_asset_matcher_no_match(mock_open, mock_exists, mock_llm_class, mock_state):
    # Setup
    mock_exists.return_value = True
    mock_open.return_value.__enter__.return_value.read.return_value = '[{"id": "DB-1", "name": "Linux DB"}]'
    
    mock_llm = MagicMock()
    mock_llm_class.return_value = mock_llm
    
    mock_result = AssetMatchResult(
        impacted_asset_ids=[],
        is_relevant=False,
        reasoning="No match found",
        impact_level="LOW"
    )
    
    with patch("langchain_core.prompts.ChatPromptTemplate.from_messages") as mock_prompt_class:
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = mock_result
        mock_prompt_class.return_value.__or__.return_value = mock_chain
        
        # Execute
        result = asset_matcher_node(mock_state)
    
    # Assert
    assert result["is_relevant"] is False
    assert len(result["impacted_assets"]) == 0
    assert result["adjusted_risk_score"] == 7.5
