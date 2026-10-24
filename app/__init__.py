@lru_cache(maxsize=None)
def get_blocker(backend: str | None = None):
    backend = (backend or os.getenv("BLOCKER", "mock")).lower()