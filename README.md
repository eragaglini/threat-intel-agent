# Threat Intel Agent 🛡️

Un agente di **Threat Intelligence** modulare progettato per automatizzare l'ingestione, la correlazione e l'analisi di indicatori di compromissione (IoC) e vulnerabilità di sicurezza, potenziato da un'architettura a due livelli e un motore di ragionamento basato su AI.

---

## 🚀 Stato Attuale del Progetto

Il progetto ha completato la **Fase 2 (AI Reasoning & Enrichment)** con l'implementazione di un grafo agentico avanzato.

### 🏗️ Layer 1: Ingestion & Storage
- **NVD (NIST):** Fetching paginato di CVE con supporto completo per CVSS v4.0, v3.1, v3.0 e v2.0.
- **CISA KEV:** Monitoraggio delle vulnerabilità sfruttate attivamente nel mondo reale.
- **AbuseIPDB:** Analisi della reputazione degli indirizzi IP.
- **EPSS (FIRST.org):** Integrazione della probabilità di exploit.
- **Persistenza:** Database **SQLite** locale ottimizzato con logica di Upsert.

### 🧠 Layer 2: LangGraph Agentic Reasoning
Un grafo di agenti intelligente che elabora le vulnerabilità attraverso un flusso di lavoro strutturato:
1.  **CVE Enrichment:** Espansione dei dettagli tecnici tramite Claude 3 Haiku.
2.  **Risk Scorer:** Calcolo di un punteggio di rischio dinamico basato su CVSS, EPSS e dati KEV.
3.  **Asset Matching:** Correlazione automatica con l'inventario asset aziendale (`assets.json`) e ricalcolo del rischio contestuale.
4.  **ATT&CK Mapping:** Mappatura deterministica e probabilistica alle tecniche MITRE ATT&CK.
5.  **Critic Node:** Validazione autonoma con cicli di riflessione (fino a 2 tentativi) in caso di bassa confidenza o errori.
6.  **Report Generator:** Generazione di report narrativi e strutturati per SOC analysts.
7.  **Persistence:** Salvataggio automatico dei report in formato JSON nella directory `reports/`.

---

## 🛠️ Stack Tecnico

- **Linguaggio:** Python 3.11+
- **Agent Framework:** [LangGraph](https://langchain-ai.github.io/langgraph/)
- **LLM Integration:** [LangChain Anthropic](https://python.langchain.com/docs/integrations/chat/anthropic/) (Claude 3.5 Sonnet & Haiku)
- **Retry Logic:** [Tenacity](https://tenacity.readthedocs.io/) (Exponential backoff per API HTTP e LLM)
- **Validazione Dati:** [Pydantic v2](https://docs.pydantic.dev/)
- **Database:** SQLite
- **Test:** Pytest, mock, requests-mock

---

## 💻 Come Iniziare

### 1. Requisiti
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurazione
Crea un file `.env` nella root del progetto:
```env
ANTHROPIC_API_KEY=tua_chiave_anthropic
NVD_API_KEY=tua_chiave_opzionale
ABUSEIPDB_API_KEY=tua_chiave_necessaria_per_IP
```

### 3. Esecuzione
```bash
# Esegui l'ingestion (Layer 1)
python3 -m layer1.main

# Esegui l'agente di analisi (Layer 2)
python3 -m layer2.main

# Esegui la suite di test
pytest
```

---

## 🔮 Visione Futura (Roadmap)

1.  **📊 Change Tracking (History):** Monitoraggio evolutivo del punteggio CVSS e dello stato KEV.
2.  **🔔 Notification Engine:** Alert automatici via Webhook o Email per vulnerabilità critiche.
3.  **🧠 Advanced RAG:** Integrazione con un Vector Database per analisi contestuale su documenti interni.
4.  **🖥️ Dashboard CLI:** Interfaccia interattiva per interrogare l'agente e visualizzare i report.
