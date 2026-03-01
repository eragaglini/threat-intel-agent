import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.attck_mapper import attck_mapper_node, TTPList
from layer2.models.state import TTP
import layer2.nodes.attck_mapper as attck_mapper_module

def test_attck_mapper_success(monkeypatch):
    state = {
        "cve_id": "CVE-TEST",
        "raw_data": {"description": "test description"},
        "enriched_data": {},
        "ttp_mappings": [],
        "confidence_scores": {"attck_mapping": 0.0},
        "errors": []
    }

    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = TTPList(ttps=[
        TTP(technique_id="T1190", name="Exploit", confidence=0.9)
    ])
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(attck_mapper_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        updates = attck_mapper_node(state)

    # Simula il merge che LangGraph fa in produzione
    final_state = {**state, **updates}

    # Assertions sullo state finale (merged)
    assert final_state["errors"] == [], f"Detected errors: {final_state['errors']}"
    assert mock_chain.invoke.called
    assert len(final_state["ttp_mappings"]) == 1
    assert final_state["ttp_mappings"][0]["technique_id"] == "T1190"
    assert final_state["confidence_scores"]["attck_mapping"] == 0.9

    # Verifica che il nodo non ritorni campi inaspettati
    assert "errors" not in updates, (
        "Il nodo non dovrebbe includere 'errors' nel return del percorso happy path"
    )


def test_attck_mapper_empty_safe(monkeypatch):
    state = {
        "cve_id": "CVE-EMPTY",
        "raw_data": {"description": "test"},
        "enriched_data": {},
        "ttp_mappings": [],
        "confidence_scores": {"attck_mapping": 0.0},
        "errors": []
    }

    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    mock_chain.invoke.return_value = TTPList(ttps=[])
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(attck_mapper_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        updates = attck_mapper_node(state)

    final_state = {**state, **updates}

    assert len(final_state["ttp_mappings"]) == 0
    assert final_state["confidence_scores"]["attck_mapping"] == 0.0

def test_attck_mapper_handles_llm_failure(monkeypatch):
    """
    Verifica che in caso di errore LLM, il nodo ritorni
    errors popolato e ttp_mappings vuoto.
    """
    state = {
        "cve_id": "CVE-FAIL",
        "raw_data": {"description": "test"},
        "enriched_data": {},
        "ttp_mappings": [],
        "confidence_scores": {"attck_mapping": 0.0},
        "errors": []
    }

    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    mock_chain.invoke.side_effect = Exception("API timeout simulato")
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(attck_mapper_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        updates = attck_mapper_node(state)

    final_state = {**state, **updates}

    assert len(final_state["ttp_mappings"]) == 0
    assert final_state["confidence_scores"]["attck_mapping"] == 0.0
    assert any("ATT&CK mapping failed" in e for e in final_state["errors"])