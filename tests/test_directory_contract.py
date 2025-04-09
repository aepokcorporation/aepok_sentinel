# test_directory_contract.py
"""
Tests for directory_contract.py, ensuring path handling, structure
validation, and symlink/Unicode spoof checks operate correctly.
"""

import os
import pytest
import shutil
import unicodedata
from pathlib import Path

from aepok_sentinel.core.directory_contract import (
    SENTINEL_RUNTIME_BASE,
    validate_runtime_structure,
    resolve_path,
    REQUIRED_DIRS,
    REQUIRED_FILES,
)

@pytest.fixture
def mock_runtime(tmp_path):
    """
    Creates a temporary mock runtime directory with the
    same sub-structure expected by Sentinel, then yields
    that path. After tests, it cleans up automatically.
    """
    # Replicate the essential structure
    base = tmp_path / "runtime"
    base.mkdir(parents=True, exist_ok=True)

    for d in REQUIRED_DIRS:
        (base / d).mkdir(exist_ok=True)
        for f in REQUIRED_FILES.get(d, []):
            file_path = base / d / f
            file_path.touch()

    # We also copy the structure so we can dynamically replace
    # the global SENTINEL_RUNTIME_BASE in tests if needed
    yield base
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_validate_runtime_structure(mock_runtime, monkeypatch):
    """
    Ensures validate_runtime_structure() succeeds with all required
    directories and files in place, and fails if anything is missing.
    """
    # Temporarily override SENTINEL_RUNTIME_BASE
    monkeypatch.setattr(
        "aepok_sentinel.core.directory_contract.SENTINEL_RUNTIME_BASE",
        mock_runtime
    )

    # This should pass with no exceptions
    validate_runtime_structure()

    # Remove one required file to confirm failure
    missing_file = mock_runtime / "config" / "trust_anchor.json"
    missing_file.unlink()

    with pytest.raises(RuntimeError) as excinfo:
        validate_runtime_structure()
    assert "Missing required file" in str(excinfo.value)


def test_resolve_path_normal_usage(mock_runtime, monkeypatch):
    """
    Ensures resolve_path returns a correct absolute path for normal usage.
    """
    monkeypatch.setattr(
        "aepok_sentinel.core.directory_contract.SENTINEL_RUNTIME_BASE",
        mock_runtime
    )
    p = resolve_path("config", "trust_anchor.json")
    assert p == (mock_runtime / "config" / "trust_anchor.json")


def test_resolve_path_unicode_normalization(mock_runtime, monkeypatch):
    """
    Ensures suspicious Unicode changes cause a ValueError.
    For example, a character with a different NFC form.
    """
    monkeypatch.setattr(
        "aepok_sentinel.core.directory_contract.SENTINEL_RUNTIME_BASE",
        mock_runtime
    )

    # Compose a path part that will change under NFC
    # e.g., the letter 'e' with combining acute vs. precomposed é
    base_char = "e\u0301"  # combining acute
    assert unicodedata.normalize("NFC", base_char) != base_char

    with pytest.raises(ValueError) as excinfo:
        resolve_path("config", base_char, "file.txt")
    assert "Path component" in str(excinfo.value)


def test_resolve_path_symlink_escaping(mock_runtime, monkeypatch):
    """
    Ensures symlinks that point outside the runtime directory are rejected.
    """
    monkeypatch.setattr(
        "aepok_sentinel.core.directory_contract.SENTINEL_RUNTIME_BASE",
        mock_runtime
    )

    # Create a subdir outside runtime
    external_dir = mock_runtime.parent / "external"
    external_dir.mkdir(exist_ok=True)
    (external_dir / "external_file.txt").touch()

    # Inside runtime/config, create a symlink pointing to external_file.txt
    malicious_link = mock_runtime / "config" / "malicious_link"
    malicious_link.symlink_to(external_dir / "external_file.txt")

    with pytest.raises(ValueError) as excinfo:
        resolve_path("config", "malicious_link")
    assert "points outside the runtime directory" in str(excinfo.value)


def test_resolve_path_internal_symlink_ok(mock_runtime, monkeypatch):
    """
    Ensures symlinks that remain within the runtime directory are allowed.
    """
    monkeypatch.setattr(
        "aepok_sentinel.core.directory_contract.SENTINEL_RUNTIME_BASE",
        mock_runtime
    )

    # Create a file in runtime/keys
    real_file = mock_runtime / "keys" / "test_key.bin"
    real_file.touch()

    # Symlink to that file from runtime/config
    link_path = mock_runtime / "config" / "test_key_link"
    link_path.symlink_to(real_file)

    resolved = resolve_path("config", "test_key_link")
    assert resolved == real_file.resolve()
    assert str(resolved).startswith(str(mock_runtime))