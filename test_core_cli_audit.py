import os

from pqtrust import AuditLog, fingerprint_bytes, fingerprint_file, load_default, where
from pqtrust.__main__ import main


def test_where_points_to_existing_file():
    assert os.path.isfile(where())


def test_default_registry_loads():
    assert len(load_default()) >= 1


def test_fingerprint_file_matches_bytes(tmp_path):
    f = tmp_path / "key.bin"
    f.write_bytes(b"hello" * 50000)
    assert fingerprint_file(f) == fingerprint_bytes(b"hello" * 50000)


def test_audit_log_is_bounded(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", capacity=3)
    for i in range(5):
        log.record("check", n=i)
    assert [e["n"] for e in log.recent()] == [2, 3, 4]
    assert len(AuditLog.tail(tmp_path / "a.jsonl", 2)) == 2


def test_cli_check_untrusted(capsys):
    assert main(["check", "0" * 64]) == 1
    assert "NOT TRUSTED" in capsys.readouterr().out


def test_cli_list(capsys):
    assert main(["list"]) == 0
    assert "ML-DSA" in capsys.readouterr().out
