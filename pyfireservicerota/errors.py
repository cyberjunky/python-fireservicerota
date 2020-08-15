"""Errors used in this library."""


class ExpiredTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating expired tokens."""

    pass


class InvalidTokenError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid tokens."""

    pass


class InvalidAuthError(Exception):
    """Raised when fireservicerota API returns a code indicating invalid credentials."""

    pass
