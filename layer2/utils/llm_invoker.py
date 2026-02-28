import logging
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log
from langchain_core.runnables import Runnable

logger = logging.getLogger(__name__)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True
)
def invoke_chain_with_retry(chain: Runnable, inputs: dict):
    """
    Invokes a LangChain chain with exponential backoff retry logic.
    """
    return chain.invoke(inputs)
