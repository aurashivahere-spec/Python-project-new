from datetime import date

import pytest

from pqtrust import Anchor, DuplicateAnchorError, TrustRegistry, UnknownAnchorError

FP1 = "a" * 64
FP2 = "b" * 64


def make(fp=FP1, name="Test", days=date(2030, 1, 1), algo="ML-DSA-65"):
    return Anchor(name, algo, fp, days)


def test_add_and_lookup():
    reg = TrustRegistry([make()])
    assert FP1 in reg and len(reg) == 1


def test_duplicate_rejected():
    reg = TrustRegistry([make()])
    with pytest.raises(DuplicateAnchorError):
        reg.add(make())


def test_revoke_makes_untrusted():
    reg = TrustRegistry([make()])
    reg.revoke(FP1)
    assert not reg.is_trusted(FP1, on=date(2026, 1, 1))


def test_revoke_unknown():
    with pytest.raises(UnknownAnchorError):
        TrustRegistry().revoke(FP1)


def test_expired_not_trusted():
    reg = TrustRegistry([make(days=date(2026, 1, 1))])
    assert not reg.is_trusted(FP1, on=date(2026, 6, 1))


def test_expiring_within_sorted():
    reg = TrustRegistry([
        make(FP1, "Late", date(2026, 12, 20)),
        make(FP2, "Soon", date(2026, 11, 20)),
        make("c" * 64, "Far", date(2035, 1, 1)),
    ])
    names = [a.name for a in reg.expiring_within(60, on=date(2026, 11, 11))]
    assert names == ["Soon", "Late"]


def test_group_by_algorithm():
    reg = TrustRegistry([make(FP1, algo="Ed25519"), make(FP2, algo="ML-DSA-65")])
    assert set(reg.group_by_algorithm()) == {"Ed25519", "ML-DSA-65"}


def test_invalid_fingerprint():
    with pytest.raises(ValueError):
        Anchor("x", "ML-DSA-65", "xyz", date(2030, 1, 1))


def test_save_load_roundtrip(tmp_path):
    path = tmp_path / "r.json"
    TrustRegistry([make(FP1), make(FP2, "Other")]).save(path)
    loaded = TrustRegistry.load(path)
    assert len(loaded) == 2 and FP2 in loaded
    assert list(tmp_path.glob("*.tmp")) == []
