"""
OpenEncrypt: Educational post-quantum (Kyber-like) offline encryption in pure Python.

WARNING: This implementation is for learning and experimentation only. It is not
constant-time, has not been audited, and should not be used to protect sensitive data
in production.
"""

__all__ = [
	"version",
]


def version() -> str:
	return "0.1.0-edu"


