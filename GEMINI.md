# Threat Intel Agent - Gemini CLI Project Context

## 🎯 Project Objective
Agente di **Threat Intelligence** modulare progettato per l'ingestione, la correlazione e l'analisi avanzata di indicatori di compromissione (IoC) e vulnerabilità (CVE/KEV), utilizzando un'architettura agentica basata su LLM.

## 🏗️ Architecture & Stack
- **Language:** Python 3.11+
- **Agent Framework:** LangGraph (Stateful, multi-node reasoning)
- **LLM:** Google Gemini 2.0 Flash (via LangChain)
- **Persistence:** SQLite (Schema indicizzato per performance $O(\log n)$)
- **Data Validation:** Pydantic Models (v2)
- **Ingestion:** Pattern Ingestor con client HTTP resiliente.

## 📂 Core Structure
- `layer1/ingestion/`: Logica di fetching per NVD, CISA KEV e AbuseIPDB.
- `layer1/database/`: Gestione persistenza e query di correlazione.
- `layer2/graph.py`: Definizione del grafo LangGraph e degli stati.
- `layer2/nodes/`: Implementazione dei nodi dell'agente (Enrichment, Scorer, Mapper, Critic).
- `layer2/models/`: Modelli Pydantic per lo stato del grafo e l'output strutturato.

## 🛠️ Key Conventions
1. **Agentic Validation:** Ogni analisi prodotta da un nodo deve essere validata da un nodo `Critic` prima della finalizzazione.
2. **Explicit SQL:** Tutte le query `INSERT` devono dichiarare esplicitamente le colonne.
3. **Structured Output:** Gli LLM devono sempre restituire dati validabili tramite Pydantic.
4. **State Management:** Lo stato del grafo (`AgentState`) è l'unica fonte di verità durante l'esecuzione dell'agente.

## 🚀 Execution Commands
```bash
# Setup ambiente
source venv/bin/activate
export PYTHONPATH=.

# Run Ingestion (Layer 1)
python3 layer1/main.py

# Run Analysis Agent (Layer 2)
python3 layer2/main.py
```

## 📈 Roadmap & Next Steps
- [x] Ingestione Base (NVD, CISA, AbuseIPDB)
- [x] Persistenza SQLite ottimizzata
- [x] Query di correlazione
- [x] **Agentic Reasoning (Layer 2):** Implementazione di LangGraph per analisi CVE.
- [ ] **Data Lineage (History Tracking):** Tabelle `_history` per tracciare il drift dei dati.
- [ ] Implementazione di un sistema di notifiche (Webhook/Email)
- [ ] Integrazione di un Vector Database (ChromaDB) per RAG.
- [ ] Dashboard CLI per visualizzazione report.
