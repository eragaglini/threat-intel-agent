import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.cve_enrichment import cve_enrichment_node, EnrichedData
import layer2.nodes.cve_enrichment as enrichment_module

def test_cve_enrichment_success(monkeypatch):
    # 1. Setup dello stato
    state = {
        "cve_id": "CVE-ENRICH",
        "raw_data": {"description": "test description"},
        "enriched_data": None,
        "confidence_scores": {"enrichment": 0.0},
        "errors": []
    }
    
    # 2. Mocking della catena
    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    
    # Risultato atteso (EnrichedData)
    mock_result = EnrichedData(
        affected_component="Comp",
        attack_vector="Net",
        impact_type="RCE",
        cwe="CWE-1"
    )
    mock_chain.invoke.return_value = mock_result
    
    # L'LLM deve restituire un oggetto (che verrà poi bypassato dal patch del prompt)
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    # 3. Patching
    # Patch della classe LLM nel modulo target
    monkeypatch.setattr(enrichment_module, "ChatGoogleGenerativeAI", lambda **kwargs: mock_llm_instance)
    
    # Patch dell'operatore pipe (|) del PromptTemplate per restituire la nostra catena mockata
    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        new_state = cve_enrichment_node(state)

    # 4. Assertions
    assert new_state["enriched_data"]["cwe"] == "CWE-1"
    assert new_state["enriched_data"]["impact_type"] == "RCE"
    # Nota: Assicurati che il tuo nodo imposti effettivamente 0.9, 
    # o adatta l'assert al valore reale impostato nel codice
    assert new_state["confidence_scores"]["enrichment"] > 0 
    assert len(new_state["errors"]) == 0

def test_cve_enrichment_failure(monkeypatch):
    state = {
        "cve_id": "CVE-FAIL",
        "raw_data": {"description": "test"},
        "enriched_data": None,
        "confidence_scores": {"enrichment": 0.0},
        "errors": []
    }
    
    mock_llm_instance = MagicMock()
    mock_chain = MagicMock()
    # Simuliamo il fallimento della chiamata LLM
    mock_chain.invoke.side_effect = Exception("AI model connection error")
    
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    monkeypatch.setattr(enrichment_module, "ChatGoogleGenerativeAI", lambda **kwargs: mock_llm_instance)

    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        new_state = cve_enrichment_node(state)

    # Verifichiamo il fallback
    assert new_state["enriched_data"] == {}
    assert len(new_state["errors"]) > 0
    assert "AI model connection error" in new_state["errors"][0]