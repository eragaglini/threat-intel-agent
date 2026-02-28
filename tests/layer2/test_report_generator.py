import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.report_generator import report_generator_node, Report
import layer2.nodes.report_generator as report_module

def test_report_generator_success(monkeypatch):
    # 1. Setup dello stato completo per il generatore di report
    state = {
        "cve_id": "CVE-REPORT",
        "risk_level": "high",
        "risk_score": 0.9,
        "raw_data": {"description": "test description"},
        "enriched_data": {"cwe": "CWE-79"},
        "ttp_mappings": [],
        "errors": [],
        "final_report": {}
    }
    
    # 2. Setup dei Mock
    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    
    # Risultato atteso (deve corrispondere alla classe Report)
    mock_result = Report(
        narrative="Test report narrative",
        structured_json='{"test": true}'
    )
    mock_chain.invoke.return_value = mock_result
    
    # Configuriamo l'LLM per restituire un mock intermedio
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    # 3. Patching
    # Patch dell'LLM nel modulo specifico
    monkeypatch.setattr(report_module, "ChatGoogleGenerativeAI", lambda **kwargs: mock_llm_instance)
    
    # Patch del Pipe del PromptTemplate
    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        new_state = report_generator_node(state)

    # 4. Assertions
    assert mock_chain.invoke.called
    assert new_state["final_report"]["narrative"] == "Test report narrative"
    assert "test" in new_state["final_report"]["structured_json"]
    assert len(new_state["errors"]) == 0

def test_report_generator_failure(monkeypatch):
    state = {
        "cve_id": "CVE-FAIL",
        "risk_level": "low",
        "risk_score": 0.2,
        "raw_data": {},
        "errors": [],
        "final_report": {}
    }
    
    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    
    # Simuliamo un errore di generazione (es. superamento token o timeout)
    mock_chain.invoke.side_effect = Exception("Generation failed")
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(report_module, "ChatGoogleGenerativeAI", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        new_state = report_generator_node(state)

    # Verifichiamo che l'errore sia stato catturato nel nodo
    assert len(new_state["errors"]) > 0
    assert "Generation failed" in str(new_state["errors"][-1])