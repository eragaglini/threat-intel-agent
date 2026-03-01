import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.report_generator import report_generator_node, Report
import layer2.nodes.report_generator as report_module


def test_report_generator_success(monkeypatch):
    state = {
        "cve_id": "CVE-REPORT",
        "risk_level": "high",
        "risk_score": 0.9,
        "adjusted_risk_score": 1.08,          # ← aggiunto: ora passato a Claude
        "risk_adjustment": {                   # ← aggiunto: ora passato a Claude
            "original_score": 0.9,
            "adjusted_score": 1.08,
            "multiplier_applied": 1.2,
            "impact_level": "HIGH",
            "rationale": "Test rationale."
        },
        "impacted_assets": ["SRV-1"],          # ← aggiunto: ora passato a Claude
        "is_relevant": True,                   # ← aggiunto: ora passato a Claude
        "raw_data": {"description": "test description"},
        "enriched_data": {"cwe": "CWE-79"},
        "ttp_mappings": [],
        "reflexion_count": 0,
        "errors": [],
        "final_report": {}
    }

    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()

    mock_result = Report(
        narrative="Test report narrative",
        structured_json='{"test": true}'
    )
    mock_chain.invoke.return_value = mock_result
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(report_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        updates = report_generator_node(state)

    # Merge come fa LangGraph in produzione
    final_state = {**state, **updates}

    assert mock_chain.invoke.called

    # Verifica final_report
    assert final_state["final_report"]["narrative"] == "Test report narrative"
    assert "test" in final_state["final_report"]["structured_json"]

    # Il percorso happy path non tocca errors — verifica sullo state merged
    assert final_state["errors"] == []

    # Verifica che il nodo NON includa errors nel return del happy path
    assert "errors" not in updates


def test_report_generator_failure(monkeypatch):
    state = {
        "cve_id": "CVE-FAIL",
        "risk_level": "low",
        "risk_score": 0.2,
        "adjusted_risk_score": None,
        "risk_adjustment": {},
        "impacted_assets": [],
        "is_relevant": False,
        "raw_data": {},
        "enriched_data": {},
        "ttp_mappings": [],
        "reflexion_count": 0,
        "errors": [],
        "final_report": {}
    }

    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    mock_chain.invoke.side_effect = Exception("Generation failed")
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(report_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        updates = report_generator_node(state)

    # Merge come fa LangGraph in produzione
    final_state = {**state, **updates}

    # Errore catturato e propagato nello state
    assert len(final_state["errors"]) > 0
    assert "Generation failed" in str(final_state["errors"][-1])

    # final_report deve essere None in caso di errore
    assert final_state["final_report"] is None