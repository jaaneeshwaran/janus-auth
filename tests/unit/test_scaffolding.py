"""Smoke tests for the repository scaffold (Task 1)."""

import janus_auth


def test_package_version_is_pinned() -> None:
    assert janus_auth.__version__ == "0.1.0"


def test_package_public_api_is_explicit() -> None:
    assert janus_auth.__all__ == ["__version__"]
