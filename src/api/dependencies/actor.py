from __future__ import annotations

from fastapi import Header, HTTPException

from src.domain.entities.actor import Actor
from src.security.actor_context import InvalidActorContextError, parse_actor_context


def get_actor(
    x_policyguard_actor: str | None = Header(default=None, alias="X-PolicyGuard-Actor"),
    x_policyguard_role: str | None = Header(default=None, alias="X-PolicyGuard-Role"),
) -> Actor:
    try:
        return parse_actor_context(x_policyguard_actor, x_policyguard_role)
    except InvalidActorContextError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
