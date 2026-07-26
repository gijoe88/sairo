"""
Per-request session propagation for the MCP server.

Tools resolve the authenticated session via ``current_session()`` instead of
reading it off the lifespan context. On the HTTP path the bearer middleware
binds a ``UserSession`` to this ContextVar for the duration of each request;
on the stdio / in-memory transport path the lifespan bootstrap sets a
process-default session that child asyncio tasks inherit.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Optional

from auth import AuthorizationError, UserSession

_request_session: ContextVar[Optional[UserSession]] = ContextVar(
    "_request_session", default=None
)


def current_session() -> UserSession:
    """Return the session bound to the current request context.

    Raises ``AuthorizationError`` if no session is bound — callers should
    treat that as a 401-equivalent (the middleware should have set one).
    """
    session = _request_session.get()
    if session is None:
        raise AuthorizationError("No authenticated session bound to this request.")
    return session


def set_session(session: UserSession):
    """Bind ``session`` to the current context and return the reset token."""
    return _request_session.set(session)


def reset_session(token) -> None:
    """Reset the ContextVar using the token returned by :func:`set_session`."""
    _request_session.reset(token)


@contextmanager
def request_session(session: UserSession):
    """Context manager that binds ``session`` for the duration of the block."""
    token = set_session(session)
    try:
        yield
    finally:
        reset_session(token)
