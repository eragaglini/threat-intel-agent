# Threat Intel Agent - Gemini CLI Project Context

## 🎯 Project Objective
Agente di **Threat Intelligence** modulare progettato per l'ingestione, la correlazione e l'analisi avanzata di indicatori di compromissione (IoC) e vulnerabilità (CVE/KEV), utilizzando un'architettura agentica basata su LLM.

## 🏗️ Architecture & Stack
- **Language:** Python 3.11+
- **Agent Framework:** LangGraph (Stateful, multi-node reasoning)
- **LLM:** Anthropic Claude 3.5 Sonnet & Claude 3 Haiku (via LangChain)
- **Persistence:** SQLite (Layer 1) & JSON Reports (Layer 2)
- **Data Validation:** Pydantic Models (v2)
- **Ingestion:** Pattern Ingestor con client HTTP resiliente.

## 📂 Core Structure
- `layer1/ingestion/`: Logica di fetching per NVD, CISA KEV, AbuseIPDB ed EPSS.
- `layer1/database/`: Gestione persistenza e query di correlazione SQLite.
- `layer2/graph.py`: Definizione del grafo LangGraph, stati e router.
- `layer2/nodes/`: Implementazione dei nodi dell'agente (Enrichment, Scorer, Matcher, Mapper, Critic, Generator).
- `layer2/models/`: Modelli Pydantic per lo stato del grafo e l'output strutturato.
- `layer2/config.py`: Configurazione centralizzata dei modelli LLM.
- `layer2/utils/llm_invoker.py`: Utility per chiamate LLM resilienti con Tenacity (Retry).
- `assets.json`: Mock CMDB per asset matching interno.
- `reports/`: Archivio report generati dall'agente (ignorato da git).

## 🛠️ Key Conventions
1. **Centralized LLM Config:** Tutti i nodi devono utilizzare i modelli definiti in `layer2/config.py`.
2. **Resilient LLM Calls:** Tutte le chiamate LLM devono passare attraverso `invoke_chain_with_retry`.
3. **Agentic Validation:** Ogni analisi prodotta deve essere validata da un nodo `Critic` con supporto alla riflessione (`reflexion_count`).
4. **State Merge:** I nodi devono restituire solo i campi aggiornati (dict) per permettere il merge automatico di LangGraph.
5. **Asset-Centric Risk:** Lo score di rischio viene ricalcolato in base alla presenza di asset impattati.

## 🚀 Execution Commands
```bash
# Setup ambiente
source venv/bin/activate

# Run Ingestion (Layer 1)
python3 -m layer1.main

# Run Analysis Agent (Layer 2)
python3 -m layer2.main

# Run Tests
pytest
```

## 📈 Roadmap & Next Steps
- [x] Ingestione Base (NVD, CISA, AbuseIPDB, EPSS)
- [x] Persistenza SQLite ottimizzata
- [x] Query di correlazione
- [x] **Agentic Reasoning (Layer 2):** Implementazione di LangGraph per analisi CVE.
- [x] **Asset Matching:** Correlazione con inventario interno.
- [x] **Self-Correction:** Cicli di riflessione del nodo Critic.
- [x] **Report Persistence:** Salvataggio report strutturati su filesystem.
- [ ] **Data Lineage (History Tracking):** Tabelle `_history` per tracciare il drift dei dati.
- [ ] Implementazione di un sistema di notifiche (Webhook/Email)
- [ ] Integrazione di un Vector Database (ChromaDB) per RAG.
- [ ] Dashboard CLI per visualizzazione report.
