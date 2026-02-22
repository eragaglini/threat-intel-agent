# Threat Intel Agent - Gemini CLI Project Context

## 🎯 Project Objective
Agente di **Threat Intelligence** modulare progettato per l'ingestione, la correlazione e la persistenza di indicatori di compromissione (IoC) e vulnerabilità (CVE/KEV) da sorgenti autorevoli (NVD, CISA, AbuseIPDB).

## 🏗️ Architecture & Stack
- **Language:** Python 3.11+
- **Persistence:** SQLite (Schema indicizzato per performance $O(\log n)$)
- **Data Validation:** Pydantic Models (v2)
- **Ingestion:** Pattern Ingestor con client HTTP resiliente (Tenacity per retry logico)
- **Database Layer:** `DatabaseManager` con transazioni atomiche e query esplicite.

## 📂 Core Structure
- `src/ingestion/`: Logica di fetching per NVD, CISA KEV e AbuseIPDB.
- `src/database/`: Gestione persistenza e query di correlazione (JOIN).
- `src/utils/`: Utility comuni (HTTP Client, Logging).
- `src/main.py`: Entry point per il PoC di ingestione.

## 🛠️ Key Conventions
1. **Explicit SQL:** Tutte le query `INSERT` devono dichiarare esplicitamente le colonne per robustezza contro evoluzioni dello schema.
2. **Batch Processing:** Utilizzare `executemany` per inserimenti massivi (es. CISA KEV) per minimizzare l'I/O sul disco.
3. **Immutability:** I dati grezzi scaricati sono validati tramite i modelli in `src/ingestion/models.py`.

## 🚀 Execution Commands
```bash
# Setup ambiente
source venv/bin/activate
export PYTHONPATH=.

# Run Ingestion PoC
python3 src/main.py
```

## 📈 Roadmap & Next Steps
- [x] Ingestione Base (NVD, CISA, AbuseIPDB)
- [x] Persistenza SQLite ottimizzata
- [x] Query di correlazione (Critical Exploited JOIN)
- [ ] **Data Lineage (History Tracking):** Implementazione di tabelle `_history` per tracciare il drift dei dati (es. variazione del `cvss_score` nel tempo) invece di sovrascrivere semplicemente il record.
- [ ] Implementazione di un sistema di notifiche (Webhook/Email)
- [ ] Integrazione di un Vector Database per analisi semantica con LLM
- [ ] Dashboard CLI per interrogazione rapida degli IoC
