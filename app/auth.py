import os
import secrets

from dotenv import load_dotenv
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

load_dotenv()

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided: str | None = Security(api_key_header)) -> None:
    expected = os.getenv("WEBHOOK_SECRET")
    if not expected:
        # Fail closed: no secret configured means nobody gets in.
        raise HTTPException(status_code=503, detail="Server auth not configured")
    if not provided or not secrets.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")