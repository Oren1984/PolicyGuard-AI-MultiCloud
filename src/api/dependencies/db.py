from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends
from sqlalchemy.orm import Session

from src.adapters.persistence.db import get_sessionmaker
from src.config import Settings, get_settings


def get_db(settings: Settings = Depends(get_settings)) -> Generator[Session, None, None]:
    factory = get_sessionmaker(settings.database_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()
