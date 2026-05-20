"""Checks for the repository license file."""
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def test_license_file_uses_mit_terms_and_owner_identity():
    license_text = (PROJECT / "LICENSE").read_text(encoding="utf-8")

    assert license_text.startswith("MIT License")
    assert "Copyright (c) 2026" in license_text
    assert "권태욱 (Taewook Kwon, ImuruKevol)" in license_text
    assert "kwon3286@season.co.kr" in license_text
    assert 'Permission is hereby granted, free of charge' in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
