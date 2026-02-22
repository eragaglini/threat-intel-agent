# Threat Intel Agent 🛡️

Un agente di **Threat Intelligence** modulare progettato per automatizzare l'ingestione, la correlazione e l'analisi di indicatori di compromissione (IoC) e vulnerabilità di sicurezza.

---

## 🚀 Stato Attuale del Progetto

Il progetto ha completato la **Fase 1 (Ingestion & Storage)**. Attualmente è in grado di:

### 📥 Ingestion Multi-Sorgente
- **NVD (NIST):** Fetching paginato di CVE con supporto completo per CVSS v4.0, v3.1, v3.0 e v2.0.
- **CISA KEV:** Monitoraggio delle vulnerabilità sfruttate attivamente nel mondo reale.
- **AbuseIPDB:** Analisi della reputazione degli indirizzi IP per identificare attività malevole.
- **EPSS (FIRST.org):** Integrazione del sistema di previsione della probabilità di exploit.

### 💾 Persistenza Ottimizzata
- Database **SQLite** locale con schema indicizzato per ricerche veloci.
- Logica di **Upsert (ON CONFLICT)**: i record vengono aggiornati solo se i dati in ingresso sono più recenti (`last_modified`), evitando scritture inutili.
- Tracciamento temporale con `fetched_at` e `updated_at` per ogni record.

### 🧪 Affidabilità & Qualità
- Suite di **Unit Test** completa con `pytest` (mocking delle API per testare edge case senza consumare quote API reali).
- Client HTTP resiliente con logica di **retry esponenziale** (via Tenacity).

---

## 🏗️ Architettura & Stack Tecnico

- **Linguaggio:** Python 3.11+
- **Validazione Dati:** [Pydantic v2](https://docs.pydantic.dev/)
- **Database:** SQLite (con supporto a transazioni atomiche `executemany`)
- **Test:** Pytest, requests-mock, pytest-mock

---

## 🛠️ Come Iniziare

### 1. Requisiti
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurazione
Crea un file `.env` nella root del progetto:
```env
NVD_API_KEY=tua_chiave_opzionale
ABUSEIPDB_API_KEY=tua_chiave_necessaria_per_IP
```

### 3. Esecuzione
```bash
# Esegui l'ingestion dimostrativa
PYTHONPATH=. python3 src/main.py

# Esegui la suite di test
PYTHONPATH=. pytest tests/
```

---

## 🔮 Visione Futura (Roadmap)

L'obiettivo finale è trasformare questo raccoglitore in un assistente decisionale intelligente:

1.  **📊 Change Tracking (History):** Non solo l'ultimo stato, ma la storia dei cambiamenti (es. "Il CVSS di questa CVE è passato da 7 a 9").
2.  **🔔 Notification Engine:** Alert automatici via Webhook o Email quando una vulnerabilità critica viene rilevata come "sfruttata attivamente" (CISA KEV).
3.  **🧠 AI Integration (RAG):** Utilizzo di un **Vector Database** (es. ChromaDB) per permettere a un LLM (Gemini) di rispondere a domande complesse sui dati ingeriti in linguaggio naturale.
4.  **🖥️ CLI Dashboard:** Un'interfaccia interattiva per interrogare rapidamente gli IoC senza scrivere SQL.

---
*Per maggiori dettagli sulle convenzioni tecniche, consulta [GEMINI.md](./GEMINI.md).*
