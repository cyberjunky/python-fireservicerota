"""Error routines used in this module."""


class FireServiceRotaError(Exception):
    """Base class for all fireservicerota exceptions."""

    pass


class ExpiredTokenError(FireServiceRotaError):
    """Raised when API returns a code indicating expired tokens."""

    pass


class InvalidTokenError(FireServiceRotaError):
    """Raised when API returns a code indicating invalid tokens."""

    pass


class InvalidAuthError(FireServiceRotaError):
    """Raised when API returns a code indicating invalid credentials."""
