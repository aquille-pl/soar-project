import os
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@lru_cache(maxsize=1)
def get_blocker():
    backend = os.getenv("BLOCKER", "mock").lower()
    if backend == "azure_nsg":
        from app.blockers.azure_nsg import AzureNsgBlocker

        return AzureNsgBlocker()
    from app.blockers.mock import MockBlocker

    return MockBlocker()