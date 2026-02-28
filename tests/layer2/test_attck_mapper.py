import pytest
from unittest.mock import MagicMock, patch
from layer2.nodes.attck_mapper import attck_mapper_node, TTPList
from layer2.models.state import TTP
import layer2.nodes.attck_mapper as attck_mapper_module

def test_attck_mapper_success(monkeypatch):
    # 1. Setup dello stato
    state = {
        "cve_id": "CVE-TEST",
        "raw_data": {"description": "test description"},
        "enriched_data": {},
        "ttp_mappings": [],
        "confidence_scores": {"attck_mapping": 0.0},
        "errors": []
    }
    
    # 2. Creazione dei Mock
    mock_llm_instance = MagicMock()
    mock_chain = MagicMock() # Questo rappresenterà la catena intera
    
    # Risultato atteso
    mock_result = TTPList(ttps=[
        TTP(technique_id="T1190", name="Exploit", confidence=0.9)
    ])
    
    # Configurazione: la catena deve restituire il risultato
    mock_chain.invoke.return_value = mock_result
    
    # Configurazione LLM: with_structured_output restituisce un mock
    mock_llm_instance.with_structured_output.return_value = MagicMock()

    # 3. Patching Strategico
    # A. Patch della classe LLM
    monkeypatch.setattr(attck_mapper_module, "ChatAnthropic", lambda **kwargs: mock_llm_instance)
    
    # B. Patch dell'operatore PIPE del PromptTemplate
    # Quando LangChain fa `prompt | structured_llm`, forziamo il ritorno del nostro mock_chain
    with patch("langchain_core.prompts.PromptTemplate.__or__", return_value=mock_chain):
        new_state = attck_mapper_node(state)

    # 4. Assertions
    # Verifichiamo che non ci siano errori (l'errore max() sparirà)
    assert new_state["errors"] == [], f"Detected errors: {new_state['errors']}"
    
    assert mock_chain.invoke.called
    assert len(new_state["ttp_mappings"]) == 1
    assert new_state["ttp_mappings"][0]["technique_id"] == "T1190"
    assert new_state["confidence_scores"]["attck_mapping"] == 0.9

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
        new_state = attck_mapper_node(state)

    assert len(new_state["ttp_mappings"]) == 0
    assert new_state["confidence_scores"]["attck_mapping"] == 0.0