# Configurazione dei modelli LLM per il Layer 2
# Modifica qui per cambiare i modelli a livello globale

LLM_CONFIG = {
    "enrichment": "claude-3-haiku-20240307",
    "attck_mapping": "claude-3-haiku-20240307",
    "report_generation": "claude-3-haiku-20240307",
    "critic": "claude-3-haiku-20240307",
}

# Opzioni comuni per i modelli
LLM_OPTIONS = {
    "temperature": 0,
    "max_retries": 5,
}
