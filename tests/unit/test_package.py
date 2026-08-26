"""Phase 0 smoke tests: the package is importable and versioned."""

from grc_agent import __version__


def test_package_version() -> None:
    assert __version__ == "0.1.0"
