# Threat Intel Agent 🛡️

Un agente di **Threat Intelligence** modulare che automatizza 
ingestione, correlazione e analisi di vulnerabilità e indicatori 
di compromissione, potenziato da un'architettura multi-layer e 
un motore di ragionamento basato su AI (Claude, Anthropic).

> **Nota:** Questo è un Proof of Concept sviluppato a scopo 
> dimostrativo. Layer 1 e Layer 2 sono implementati e coperti 
> da test. Layer 3 e Layer 4 sono progettati architetturalmente 
> e in fase di sviluppo.

---

## 🏗️ Architettura

```text
┌─────────────────────────────────────────────────────────────┐
│  Layer 1 — Data Ingestion                          [✅ LIVE] │
│  NVD API → CISA KEV → AbuseIPDB → EPSS → SQLite            │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│  Layer 2 — Agentic Reasoning (LangGraph)           [✅ LIVE] │
│                                                             │
│  cve_enrichment → risk_scorer → asset_matcher               │
│       → attck_mapper → [critic] → report_generator          │
│                            ↑           │                    │
│                            └───────────┘                    │
│                         (reflexion loop,                    │
│                          max 2 cicli)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│  Layer 3 — Storage & Retrieval                  [📐 DESIGN] │
│  ChromaDB · sentence-transformers · RAG su NIST/ATT&CK      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│  Layer 4 — Output STIX 2.1                      [📐 DESIGN] │
│  stix2 · Bundle CVE/TTP/Report · Export TAXII-ready         │
└─────────────────────────────────────────────────────────────┘
```

---

## ✅ Layer 1: Data Ingestion & Storage

Pipeline modulare di acquisizione dati da fonti pubbliche:

| Sorgente | Dati raccolti |
|:---------|:--------------|
| **NVD (NIST)** | CVE feed con CVSS v2/v3/v4, descrizioni, riferimenti |
| **CISA KEV** | Vulnerabilità sfruttate attivamente, flag ransomware |
| **AbuseIPDB** | Reputazione IP, confidence score, categorie abuso |
| **EPSS (FIRST.org)** | Probabilità di exploit nei prossimi 30 giorni |

**Caratteristiche implementative:**
- **Upsert intelligente** su SQLite con `ON CONFLICT` (aggiorna solo se i dati sono più recenti).
- **Retry con backoff esponenziale** via Tenacity (gestione rate-limit 429/500).
- **Batch processing** paginato (NVD) e in chunk da 100 (EPSS, per evitare errori 414).
- **Tracciamento temporale** con `fetched_at` e `updated_at`.

---

## 🧠 Layer 2: Agentic Reasoning Pipeline

Grafo agentico stateful implementato con LangGraph.  
Ogni nodo ritorna solo i campi aggiornati — il merge è gestito dal framework (pattern corretto per LangGraph).

| Nodo | Funzione |
|:-----|:---------|
| `cve_enrichment` | Estrae affected component, attack vector, CWE via Claude Haiku |
| `risk_scorer` | Calcola risk score composito: CVSS×0.4 + EPSS×0.4 + KEV×0.2 |
| `asset_matcher` | Correla CVE con inventario asset (CMDB mock), aggiusta risk score per contesto |
| `attck_mapper` | Mappa su tecniche MITRE ATT&CK con confidence score per tecnica |
| `critic` | Valida output, attiva reflexion loop (max 2 cicli) se confidence bassa |
| `report_generator` | Genera report narrativo + JSON strutturato con `risk_adjustment` auditabile |
| `save_report` | Persiste report su filesystem in `reports/` |

### Esempio di Output

```json
{
  "cve_id": "CVE-2025-64446",
  "vulnerability_name": "Fortinet FortiWeb Path Traversal",
  "original_risk_score": 0.412,
  "adjusted_risk_score": 0.4532,
  "risk_adjustment": {
    "multiplier_applied": 1.1,
    "impact_level": "MEDIUM",
    "rationale": "Asset FW-FORTI-01 impattato. Moltiplicatore 1.1x applicato."
  },
  "impacted_assets": ["FW-FORTI-01"],
  "ttp_mappings": [
    {"technique_id": "T1190", "name": "Exploit Public-Facing Application", "confidence": 0.9},
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "confidence": 0.8},
    {"technique_id": "T1068", "name": "Exploitation for Privilege Escalation", "confidence": 0.7}
  ],
  "reflexion_cycles": 0
}
```

---

## 📐 Layer 3: Storage & Retrieval (Progettato)

Vector database per RAG su documenti tecnici:
- **ChromaDB** (in-memory o persistent) con embedding `sentence-transformers/all-MiniLM-L6-v2`.
- Indicizzazione di NIST SP 800, MITRE ATT&CK JSON, advisory vendor.
- Query semantiche per augmentare i prompt LLM (riduzione allucinazioni su contenuti tecnici specifici).
- Hybrid search con filtering per metadati (fonte, data, categoria).

---

## 📐 Layer 4: Output STIX 2.1 (Progettato)

Export in formato standard per intelligence sharing:
- Bundle STIX 2.1 con oggetti `Vulnerability`, `Attack-Pattern`, `Report` e relazioni esplicite (`uses`, `indicates`).
- Libreria `stix2` per serializzazione e validazione schema.
- Compatibile con endpoint TAXII per condivisione inter-organizzativa.

---

## 🛠️ Stack Tecnico

| Componente | Tecnologia |
|:-----------|:-----------|
| Linguaggio | Python 3.11+ |
| Agent Framework | LangGraph |
| LLM | Claude 3.5 Sonnet / Claude 3 Haiku (Anthropic) |
| Data Validation | Pydantic v2 |
| HTTP Client | Requests + Tenacity (retry/backoff) |
| Database | SQLite |
| Testing | Pytest + pytest-mock + requests-mock |

---

## ⚠️ Limitazioni Note (PoC)

| Limitazione | Dettaglio |
|:------------|:----------|
| **EPSS score** | Usato default `0.05` se non disponibile in `raw_data`. L'integrazione EPSS reale è nel Layer 1 ma richiede join con tabella `epss_scores`. |
| **Asset inventory** | CMDB mock statico (`assets.json`). Non integrato con CMDB reale. |
| **Risk scorer** | CVE con CVSS identico e EPSS mancante producono score identici. |
| **Scope** | Progettato per analisi batch, non real-time streaming. |
| **ATT&CK mapping** | Basato su LLM, non su similarity search su embeddings (Layer 3). |

---

## 💻 Setup

```bash
# Clona e configura ambiente
git clone <repo>
cd threat-intel-agent
python3 -m venv venv
source venv/bin/activate

# Dipendenze produzione
pip install -r requirements.txt

# Dipendenze sviluppo e test
pip install -r requirements-dev.txt

# Variabili d'ambiente
cp .env.example .env
# Compila: ANTHROPIC_API_KEY, NVD_API_KEY, ABUSEIPDB_API_KEY
```

### Esecuzione

```bash
# Layer 1 — Ingestion
python3 -m layer1.main

# Layer 2 — Analisi agentica
python3 -m layer2.main

# Test suite (31 test)
pytest
```

---

## 📁 Struttura del Progetto

```text
threat-intel-agent/
├── layer1/
│   ├── ingestion/          # NVD, CISA, AbuseIPDB, EPSS
│   ├── database/           # SQLite con upsert intelligente
│   ├── utils/              # HTTP client resiliente
│   └── main.py
├── layer2/
│   ├── nodes/              # Nodi del grafo LangGraph
│   │   ├── cve_enrichment.py
│   │   ├── risk_scorer.py
│   │   ├── asset_matcher.py
│   │   ├── attck_mapper.py
│   │   ├── critic.py
│   │   └── report_generator.py
│   ├── models/
│   │   └── state.py        # AgentState TypedDict
│   ├── utils/              # LLM invoker con retry
│   ├── graph.py            # Definizione grafo e routing
│   ├── config.py           # Configurazione LLM
│   └── main.py
├── tests/
│   ├── layer1/             # Test ingestion e DB
│   └── layer2/             # Test logica agentica
├── assets.json             # CMDB mock
├── reports/                # Output JSON generati
├── requirements.txt        # Dipendenze produzione
├── requirements-dev.txt    # Dipendenze sviluppo/test
└── .env.example
```
