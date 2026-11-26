"""Top-level import shim for blindcore.zero_check_py."""

from blindcore.zero_check_py import Finding, check_ast_module, check_ast_path, main

__all__ = [
    "Finding",
    "check_ast_module",
    "check_ast_path",
    "main",
]

if __name__ == "__main__":
    raise SystemExit(main())
