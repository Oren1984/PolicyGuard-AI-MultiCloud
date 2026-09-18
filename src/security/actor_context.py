"""Header-based actor identity for the POC (spec section 12: "Use
header-based identity only as a clearly documented POC boundary").

This is an explicit, documented POC boundary -- not production-grade
identity. It trusts two request headers as-is:

    X-PolicyGuard-Actor: a free-text but length- and charset-limited actor id
    X-PolicyGuard-Role:  one of ActorRole's values

Production hardening (OIDC/OAuth2, enterprise IdP, signed tokens, mTLS) is a
known limitation documented for a later phase's docs/ (mirrors the sibling
ChangeGuard AI MultiCloud project's identical boundary) and must not be
implemented as an afterthought bolted onto this header scheme.

Deliberate deviation from the ChangeGuard style reference: this module
resolves headers directly into the domain's own `Actor` entity
(src/domain/entities/actor.py) rather than introducing a second, parallel
"ActorContext" value object. PolicyGuard's Phase 1 domain and every use case
already take `actor: Actor` -- adding a distinct API-layer identity type
would just require an extra conversion step at every call site for no
benefit. `display_name` has no separate source in this header scheme, so it
is set equal to the actor id.
"""

from __future__ import annotations

import re

from src.domain.entities.actor import Actor
from src.domain.enums.actor_role import ActorRole

ACTOR_HEADER = "X-PolicyGuard-Actor"
ROLE_HEADER = "X-PolicyGuard-Role"

_ACTOR_PATTERN = re.compile(r"^[A-Za-z0-9_.\-@]{1,128}$")


class InvalidActorContextError(Exception):
    pass


def parse_actor_context(actor_header: str | None, role_header: str | None) -> Actor:
    if not actor_header or not role_header:
        raise InvalidActorContextError(f"both {ACTOR_HEADER} and {ROLE_HEADER} headers are required")
    if not _ACTOR_PATTERN.match(actor_header):
        raise InvalidActorContextError(f"{ACTOR_HEADER} contains invalid characters or is too long")
    try:
        role = ActorRole(role_header.strip().lower())
    except ValueError as exc:
        valid = ", ".join(r.value for r in ActorRole)
        raise InvalidActorContextError(f"{ROLE_HEADER} must be one of: {valid}") from exc
    return Actor(actor_id=actor_header, display_name=actor_header, role=role)
