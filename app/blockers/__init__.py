import os
from functools import cache

from dotenv import load_dotenv

load_dotenv()


@cache
def get_blocker(backend: str | None = None):
    backend = (backend or os.getenv("BLOCKER", "mock")).lower()
    if backend == "azure_nsg":
        from app.blockers.azure_nsg import AzureNsgBlocker

        return AzureNsgBlocker()
    from app.blockers.mock import MockBlocker

    return MockBlocker()