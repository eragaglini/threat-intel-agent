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
- **Retry con backoff esponenziale** via Tenacity (gestione rate-limit HTTP 429/5xx).
- **Batch processing** paginato (NVD) e in chunk (EPSS) per ottimizzare le performance.
- **Tracciamento temporale** con `fetched_at` e `updated_at`.

---

## 🧠 Layer 2: Agentic Reasoning Pipeline

Grafo agentico stateful implementato con LangGraph.  
Ogni nodo ritorna solo i campi aggiornati — il merge dello stato è gestito automaticamente dal framework.

| Nodo | Funzione |
|:-----|:---------|
| `cve_enrichment` | Estrae affected component, attack vector e CWE via Claude Haiku |
| `risk_scorer` | Calcola risk score composito: CVSS×0.4 + EPSS×0.4 + KEV×0.2 |
| `asset_matcher` | Correla CVE con inventario asset (CMDB mock) e aggiusta il risk score |
| `attck_mapper` | Mappa su tecniche MITRE ATT&CK con relativi confidence score |
| `critic` | Valida l'analisi e attiva reflexion loop (max 2 cicli) se necessario |
| `report_generator` | Genera report narrativo e JSON strutturato per SOC analysts |
| `save_report` | Persiste il report finale in formato JSON nella cartella `reports/` |

### Esempio di Output Generato

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
    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "confidence": 0.8}
  ],
  "reflexion_cycles": 0
}
```

---

## 📐 Layer 3: Storage & Retrieval (Progettato)

Vector database per RAG (Retrieval-Augmented Generation) su documenti tecnici:
- **ChromaDB** con embedding `sentence-transformers/all-MiniLM-L6-v2`.
- Indicizzazione di NIST SP 800, MITRE ATT&CK JSON e advisory dei vendor.
- Riduzione delle allucinazioni tramite recupero di contesto tecnico specifico.

---

## 📐 Layer 4: Output STIX 2.1 (Progettato)

Export in formato standard per Cyber Threat Intelligence sharing:
- Generazione di bundle STIX 2.1 (Vulnerability, Attack-Pattern, Relationship).
- Utilizzo della libreria `stix2` per validazione e serializzazione.
- Supporto per integrazione con piattaforme MISP/OpenCTI via TAXII.

---

## 🛠️ Stack Tecnico

| Componente | Tecnologia |
|:-----------|:-----------|
| Linguaggio | Python 3.11+ |
| Agent Framework | LangGraph |
| LLM | Claude 3.5 Sonnet / Claude 3 Haiku (Anthropic) |
| Data Validation | Pydantic v2 |
| HTTP Client | Requests + Tenacity |
| Database | SQLite |
| Testing | Pytest + pytest-mock + requests-mock |

---

## 💻 Setup & Esecuzione

```bash
# 1. Clona e configura ambiente
git clone <repo>
cd threat-intel-agent
python3 -m venv venv
source venv/bin/activate

# 2. Installa dipendenze
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Configura .env
cp .env.example .env
# Necessario: ANTHROPIC_API_KEY
```

### Comandi principali

```bash
# Avvia Ingestion (Layer 1)
python3 -m layer1.main

# Avvia Analisi Agentica (Layer 2)
python3 -m layer2.main

# Esegui i test
pytest
```

---

## 📁 Struttura del Progetto

```text
threat-intel-agent/
├── layer1/                 # Ingestion & Database
│   ├── ingestion/          # Ingestors (NVD, CISA, etc.)
│   ├── database/           # SQLite logic & Schema
│   └── main.py
├── layer2/                 # Agentic Reasoning
│   ├── nodes/              # Nodi del grafo (Logic)
│   ├── models/             # AgentState & Pydantic models
│   ├── utils/              # LLM invoker & retry
│   ├── graph.py            # Workflow definition
│   └── main.py
├── tests/                  # Suite di test unitari e integration
├── assets.json             # Mock CMDB (Internal Assets)
├── reports/                # Output generati (Ignorato da git)
├── requirements.txt        # Dipendenze core
└── requirements-dev.txt    # Dipendenze dev/test
```
