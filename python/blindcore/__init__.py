"""BlindCore Python utilities namespace."""

from __future__ import annotations

__all__ = ["Finding", "check_ast_module", "check_ast_path", "main"]


def __getattr__(name: str):
    if name in __all__:
        from . import zero_check_py
        return getattr(zero_check_py, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
